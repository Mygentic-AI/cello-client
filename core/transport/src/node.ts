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
import { FaultTolerance } from "@libp2p/interface";
import { tcp } from "@libp2p/tcp";
import { webSockets } from "@libp2p/websockets";
import { noise } from "@chainsafe/libp2p-noise";
import { yamux } from "@chainsafe/libp2p-yamux";
import { circuitRelayServer, circuitRelayTransport } from "@libp2p/circuit-relay-v2";
import { dcutr } from "@libp2p/dcutr";
import { autoNAT } from "@libp2p/autonat";

/** AutoNAT dial-back protocol. Default prefix "libp2p"; see @libp2p/autonat protocolPrefix. */
const AUTONAT_PROTOCOL = "/libp2p/autonat/1.0.0";
import { identify } from "@libp2p/identify";
import { generateKeyPair, generateKeyPairFromSeed } from "@libp2p/crypto/keys";
import { multiaddr } from "@multiformats/multiaddr";
import type { Multiaddr } from "@multiformats/multiaddr";
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

/**
 * The set of hosts a node was CONFIGURED to listen on / announce — excluded from
 * dialability because configuration is not dial-back confirmation.
 *
 * DOD-NAT-REACHABILITY-1: do NOT expand a wildcard listen host (0.0.0.0 / ::) to
 * the machine's interface addresses. It looks like the safe thing to do under the
 * 0.0.0.0 default, and it is wrong: libp2p's address manager already handles this
 * exactly right. A PUBLIC transport address starts `verified: false`
 * (libp2p/dist/src/address-manager/transport-addresses.js — `verified:
 * !isNetworkAddress(ma)`, with private addresses verified immediately), and
 * getMultiaddrs() returns ONLY verified addresses. So a firewalled public-IP host
 * never surfaces its public address at all, and there is nothing to suppress.
 * Expanding the wildcard here would instead suppress that address in the one case
 * where it is REAL — a genuinely reachable public host whose address AutoNAT has
 * confirmed — pinning it to dialable:false forever and forcing it onto a relay it
 * does not need. Exported for direct unit-testing.
 */
export function buildConfiguredHosts(listenAddresses: string[], announceAddresses?: string[]): Set<string> {
  const configuredHosts = new Set<string>();
  for (const a of [...listenAddresses, ...(announceAddresses ?? [])]) {
    const host = extractHost(a);
    if (host !== null) configuredHosts.add(host);
  }
  return configuredHosts;
}

/**
 * Is this string a well-formed multiaddr?
 *
 * DOD-NAT-REACHABILITY-1: circuit-relay listen addresses are built from relay
 * endpoints supplied by the DIRECTORY — data from off this machine. A malformed
 * entry (a `wss://` URL, a bare peer id, anything not a multiaddr) throws inside
 * libp2p's node construction, which would take the whole standing receiver down
 * and leave the agent deaf to ALL inbound. Callers validate before listening, so
 * a bad endpoint costs one relay, never the receiver.
 */
export function isValidMultiaddr(addr: string): boolean {
  try {
    multiaddr(addr);
    return true;
  } catch {
    return false;
  }
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
 * DOD-NAT-REACHABILITY-1: standing receivers now listen on 0.0.0.0 by default,
 * which does NOT weaken this. libp2p only surfaces VERIFIED addresses through
 * getMultiaddrs(), and a public transport address stays unverified until AutoNAT
 * confirms it (see buildConfiguredHosts) — so a firewalled public-IP host never
 * offers one here at all, and a wildcard bind on a NAT'd machine yields only
 * private interface addresses, which isPubliclyDialable already rejects.
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
  #connectionMonitorPolicy: ResolvedConnectionMonitorConfig = { abortConnectionOnPingFailure: true };
  readonly keyProvider: KeyProvider;
  // Dialability observable, updated on each AutoNAT probe cycle (surfaced by
  // libp2p as a 'self:peer:update' event).
  #dialability: Dialability = { ...DEFAULT_DIALABILITY };
  readonly #dialabilityListeners = new Set<(d: Dialability) => void>();
  // Hosts this node was explicitly configured to listen on / announce. These are
  // NOT dial-back-confirmed, so they are excluded from dialability — only
  // AutoNAT-confirmed observed addresses count.
  readonly #configuredHosts: ReadonlySet<string>;
  // DOD-NAT-REACHABILITY-1: whether a non-circuit (TCP/WS) listen address was
  // configured. When circuit listen entries force NO_FATAL fault tolerance,
  // start() re-checks that the non-circuit listeners actually materialised —
  // NO_FATAL must not silently absorb a real EADDRINUSE.
  readonly #expectsDirectListener: boolean;
  // Whether ANY circuit listen entry was configured (drives the circuit-only
  // zero-listener refusal in start()).
  readonly #hasCircuitListen: boolean;
  readonly #dropAutonatResponder: boolean;
  /**
   * DOD-M15-IDLE-CONNS-1. Set once by createNode from the SAME object libp2p was given, so the
   * reported policy cannot drift from the configured one — the discipline
   * `resolveConnectionMonitorConfig` already states: what libp2p is configured with is what the
   * node reports, by construction rather than by two call sites agreeing.
   */
  #connectionLimits: ResolvedConnectionLimits = resolveConnectionLimits({});
  /** The idle-connection sweep, when this node runs one. Cleared in stop() so it cannot outlive it. */
  #idleReaperTimer: ReturnType<typeof setInterval> | null = null;
  #idleReaperConfig: {
    graceMs: number;
    sweepIntervalMs: number;
    onReaped?: (event: IdleReapEvent) => void;
    onObserved?: (counts: ConnectionCounts) => void;
  } | null = null;
  /** Peers the reaper must never hang up — the reserved relay and the named counterparty. */
  #idleReaperSpared: (peerId: string) => boolean = () => false;
  /**
   * Connection ids observed carrying at least one stream. The activity bit F1 was missing.
   *
   * Keyed on CONNECTION id, not peer id: a peer may hold several connections and the question is
   * about this one. Pruned to live connections on every sweep so a long-lived node does not
   * accumulate ids for connections that closed months ago.
   */
  readonly #everCarriedStream = new Set<string>();

  constructor(
    libp2p: Libp2p,
    keyProvider: KeyProvider,
    configuredHosts: ReadonlySet<string>,
    expectsDirectListener: boolean,
    hasCircuitListen: boolean,
    dropAutonatResponder: boolean = false,
  ) {
    this.#libp2p = libp2p;
    this.keyProvider = keyProvider;
    this.#configuredHosts = configuredHosts;
    this.#expectsDirectListener = expectsDirectListener;
    this.#hasCircuitListen = hasCircuitListen;
    this.#dropAutonatResponder = dropAutonatResponder;
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
    // Drop the AutoNAT RESPONDER on client nodes, keeping the prober half.
    //
    // @libp2p/autonat's responder answers a dial-back request by calling openConnection(peer) --
    // which RETURNS AN ALREADY-OPEN CONNECTION -- and then closes it in a `finally`. On a client
    // that connection is the one carrying directory signaling, so the close sends yamux GoAway and
    // kills every stream on it. Observed as registration failing with `signaling_lost` ~2ms after
    // `directory.signaling.connected`, against a directory that had done nothing wrong.
    //
    // Only the responder is removed. The prober half opens OUTBOUND streams and needs no inbound
    // handler, so getDialability() (DOD-NAT-REACHABILITY-1, which wraps the libp2p observable) is
    // unaffected. A client has no reason to serve dial-back anyway -- it is not infrastructure;
    // directories and relays keep the responder for exactly that purpose.
    if (this.#dropAutonatResponder) {
      try {
        await this.#libp2p.unhandle(AUTONAT_PROTOCOL);
      } catch {
        // Never registered (autonat absent or renamed upstream) -- nothing to remove.
      }
    }
    // Restore the invariant NO_FATAL relaxed: if a direct (non-circuit) listen
    // address was configured, at least one direct listener must exist. A failed
    // circuit reservation is a tolerated degradation; a failed TCP bind is not.
    if (
      this.#expectsDirectListener &&
      !this.#libp2p.getMultiaddrs().some((ma) => !ma.toString().includes("/p2p-circuit"))
    ) {
      await this.#libp2p.stop();
      throw {
        reason: "listen_failed",
        message: "no direct (non-circuit) listener materialised for the configured listen addresses",
      };
    }
    // Circuit-ONLY listen set (no direct addr configured): NO_FATAL applies and
    // the direct-listener check above is vacuous, so a dead relay would yield a
    // running node with ZERO listeners — indistinguishable from healthy. Refuse.
    if (!this.#expectsDirectListener && this.#hasCircuitListen && this.#libp2p.getMultiaddrs().length === 0) {
      await this.#libp2p.stop();
      throw {
        reason: "listen_failed",
        message: "no listener of any kind materialised for a circuit-only listen set (every relay unreachable)",
      };
    }
    // Armed by createNode; started here so the interval's lifetime is exactly the node's running
    // lifetime, and a node that was built but never started leaves nothing behind.
    this.#startIdleReaper();
  }

  async stop(): Promise<void> {
    // Before libp2p, so a sweep cannot fire against a stopping node and log a hangUp failure that
    // reads like a fault. A timer that outlives its node is how a "stopped" daemon keeps working.
    if (this.#idleReaperTimer !== null) {
      clearInterval(this.#idleReaperTimer);
      this.#idleReaperTimer = null;
    }
    await this.#libp2p.stop();
  }

  /** The connection-manager policy libp2p was actually given. */
  getConnectionLimits(): ResolvedConnectionLimits {
    return this.#connectionLimits;
  }

  /** Set by createNode with the resolved object — never a second copy. */
  setConnectionLimits(limits: ResolvedConnectionLimits): void {
    this.#connectionLimits = limits;
  }

  /**
   * DOD-M15-IDLE-CONNS-1 — name the peers the idle reaper must never hang up.
   *
   * The daemon calls this with the gater's reserved-relay slot and the directory peers. Left as a
   * setter rather than a constructor argument because the reserved relay CHANGES: a reservation is
   * lost and retaken against a different relay, and a predicate captured once at construction would
   * go on sparing a relay this node no longer talks to while reaping the one it does.
   */
  setIdleReaperSpared(isSpared: (peerId: string) => boolean): void {
    this.#idleReaperSpared = isSpared;
  }

  /**
   * Arm the idle sweep. The TIMER does not start here — `start()` starts it, so a node that is
   * built and never started leaves no interval behind, and a stop()/start() cycle gets a fresh one.
   */
  enableIdleReaper(config: {
    graceMs: number;
    sweepIntervalMs: number;
    onReaped?: (event: IdleReapEvent) => void;
    onObserved?: (counts: ConnectionCounts) => void;
  }): void {
    this.#idleReaperConfig = config;
  }

  #startIdleReaper(): void {
    const config = this.#idleReaperConfig;
    if (config === null || this.#idleReaperTimer !== null) return;
    this.#idleReaperTimer = setInterval(() => {
      // Review F5: `getConnections()` and `isSpared` both sit outside the try below, and `isSpared`
      // reaches into the daemon's gater. An unhandled rejection here takes the whole daemon down —
      // a hazard `session-node-manager.ts` already names in exactly those words.
      void this.#sweepIdleConnections().catch((err: unknown) => {
        config.onReaped?.({
          peerId: "",
          ageMs: 0,
          reason: "sweep_failed",
          error: err instanceof Error ? err.message : String(err),
        });
      });
    }, config.sweepIntervalMs);
    // Node keeps the event loop alive for a pending interval; a daemon that has stopped serving
    // must still be able to exit.
    this.#idleReaperTimer.unref?.();
  }

  async #sweepIdleConnections(): Promise<void> {
    const config = this.#idleReaperConfig;
    if (config === null) return;
    const now = Date.now();
    const connections = this.getConnections();

    // Record activity BEFORE judging. A connection seen carrying a stream even once is never a
    // candidate again, whatever libp2p later does with its closed streams.
    recordStreamActivity(this.#everCarriedStream, connections);

    // C4: the count the DoD asks for, reported every sweep. Emitted BEFORE any hang-up so the
    // number describes what was observed, not what survived.
    config.onObserved?.({
      total: connections.length,
      inbound: connections.filter((c) => c.direction === "inbound").length,
      neverSpoke: connections.filter(
        (c) => c.direction === "inbound" && !this.#everCarriedStream.has(c.id),
      ).length,
      maxConnections: this.#connectionLimits.maxConnections,
    });

    const oldestByPeer = new Map<string, number>();
    for (const c of connections) {
      const prior = oldestByPeer.get(c.peerId);
      if (prior === undefined || c.openedAt < prior) oldestByPeer.set(c.peerId, c.openedAt);
    }

    const doomed = selectIdleConnections({
      connections,
      now,
      isSpared: this.#idleReaperSpared,
      hasEverCarriedStream: (id) => this.#everCarriedStream.has(id),
      graceMs: config.graceMs,
    });
    for (const peerId of doomed) {
      try {
        await this.hangUp(peerId);
        // Review F3: a hang-up that tells nobody is indistinguishable from the thing simply not
        // happening — which is what the operator concludes when their next send returns
        // `no_connection` and nothing anywhere names the local sweep.
        config.onReaped?.({
          peerId,
          ageMs: now - (oldestByPeer.get(peerId) ?? now),
          reason: "never_carried_a_stream",
        });
      } catch (err: unknown) {
        // NOT swallowed. `hangUp` throws a NAMED `invalid_peer_id` written precisely so a malformed
        // id is not read as a connection problem; an empty catch destroys that distinction and
        // returns this code to the error substitution it was written to prevent. Reported and the
        // loop continues, so one bad peer does not cancel the sweep for every other connection.
        config.onReaped?.({
          peerId,
          ageMs: now - (oldestByPeer.get(peerId) ?? now),
          reason: "hangup_failed",
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
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
    // libp2p v3 StreamHandler receives (stream, connection). The connection's remotePeer is the
    // Noise-authenticated transport identity — passed through so channel-binding handlers (M12
    // anti-entropy) can pin against it. Single-arg handlers simply ignore the second parameter.
    const streamHandler: StreamHandler = (stream: Stream, connection) =>
      handler(stream, connection?.remotePeer?.toString());
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
      // `invalid_peer_id`, matching hangUp — NOT `connection_lost`, which it used to be. A string
      // that does not parse is a configuration fault, and calling it a lost connection sends the
      // caller into connection repair for it: the relay's evict-and-redial path now fires on
      // `connection_lost`, so a typo'd directory peer id produced an eviction attempt and an
      // operator-facing reading blaming a stale handle. Callers that genuinely want "the link is
      // unusable" still get `connection_lost` from `no_connection` and `mapStreamError` below.
      throw {
        reason: "invalid_peer_id",
        peerId: peerIdStr,
        message: `Invalid peer ID: ${peerIdStr}`,
      };
    }

    const connections = this.#libp2p.getConnections(peerId);
    const openConn = connections.find(
      (c) => c.status === "open"
    );

    if (!openConn) {
      // DOD-M12B-REDIAL-1: `no_connection` is DISTINCT from `connection_lost`, and the difference
      // decides whether re-dialling can help. This is the one condition a dial fixes — there is no
      // connection at all. `connection_lost` is `mapStreamError`'s catch-all default, so it also
      // covers a stream that failed on a perfectly healthy connection (the per-protocol stream cap,
      // DOD-M12B-ACK-1), where a dial fixes nothing and only shows the counterparty a connection
      // request caused by a defect on this side.
      throw {
        reason: "no_connection",
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

  getConnections(): Array<{
    id: string;
    peerId: string;
    encryption: string | undefined;
    remoteAddr?: string;
    status: string;
    muxerStatus?: string;
    direction: "inbound" | "outbound";
    openedAt: number;
    streamCount: number;
  }> {
    return this.#libp2p.getConnections().map((c) => ({
      // Per-CONNECTION id. A peer may hold several and the activity bit is about one of them.
      id: c.id,
      peerId: c.remotePeer.toString(),
      encryption: c.encryption,
      // DOD-M15-IDLE-CONNS-1: the three fields a reaper needs, and the three an operator needs to
      // see a flood instead of inferring one. Nothing reported a connection count before this —
      // which is why the DoD's own instruction to "measure a healthy daemon's connection count
      // first" could not be followed: the measurement did not exist.
      direction: c.direction,
      openedAt: c.timeline.open,
      streamCount: c.streams.length,
      // DOD-M12-CONN-OBSERVE-1: the SOCKET status, which is not the muxer's. libp2p checks the two
      // separately in `newStream` — muxer first — so a stream failing with
      // `The connection muxer is "closed" and not "open"` returns before the socket is looked at,
      // and the caller cannot tell a dead muxer on a live socket from a connection that is dead
      // through. Those need different fixes: the first is repaired by evicting and redialling, the
      // second by nothing on this side. Exposed because `dial()` resolves from the registry
      // whenever a registered connection reads `open` here, which is what makes a plain redial a
      // no-op against a dead muxer.
      status: c.status,
      // DOD-M12-CONN-MUXER-OBSERVE-1: the OTHER state, and the one the failure actually lives in.
      //
      // `status` above is the socket. The muxer is the layer that carries data, it has its OWN
      // status, and `newStream` checks the muxer FIRST — so a connection can read `status: "open"`
      // while every stream on it fails with `The connection muxer is "closed" and not "open"`. That
      // combination is the entire M12 Tier P5 defect, and until this field existed it was invisible:
      // the error returns before the socket is examined, so neither value alone identifies it.
      //
      // READ OFF THE RUNTIME OBJECT, deliberately narrowly. libp2p does not put `muxer` on its
      // public `Connection` type (verified in @libp2p/interface 3.2.2), but the implementation class
      // carries it — `connection.js` guards on `this.muxer.status` to throw the very error above.
      // Optional, and `undefined` when absent: if a future libp2p moves it, this must go MISSING
      // rather than silently reporting "open" for a muxer nobody looked at, which would recreate
      // exactly the blindness the field removes.
      // OWED: drop the cast when libp2p exposes muxer state on the public type.
      muxerStatus: (c as unknown as { muxer?: { status?: string } }).muxer?.status,
      // DOD-M12B-RESPONDER-ADDR-1: the address this peer is reachable at, which the RESPONDER
      // otherwise never learns. It dialled nobody, so after an interruption it has nothing to dial
      // back with — measured live 2026-08-18, `session.transport.redial.unavailable`, "this side
      // holds no address for the counterparty". The connection has always known it; nothing exposed
      // it. A relayed address (`/p2p-circuit`) is a valid dial target too, so both kinds are given.
      remoteAddr: c.remoteAddr.toString(),
    }));
  }

  /**
   * DOD-M12-CONN-EVICT-1: drop every connection to a peer so the next dial must build a new one.
   *
   * `libp2p.dial()` does NOT always reach the network. `openConnection` calls
   * `findExistingConnection`, which filters registered connections on `con.status === 'open'` and
   * never inspects the muxer, and returns the first match. So when a connection's muxer dies while
   * its socket still reads open, every redial resolves from the registry and hands the same dead
   * object back — the repair runs, reports success, and changes nothing. Evicting is what makes the
   * redial able to work at all.
   *
   * `{ force: true }` on the dial was the alternative and is worse: it opens a second connection
   * but LEAVES the corpse registered, where `newStream`'s own `find(c => c.status === "open")` can
   * select it again on the next call.
   *
   * Resolves quietly when no connection exists — callers reach this on a failure path where the
   * connection may already be gone, and throwing there would turn a recoverable stale handle into
   * a failure of the repair itself.
   */
  /**
   * DOD-M15-RELAYSLOTS-1 — release the circuit reservation held for `peerId`. See the interface
   * declaration for why `hangUp` is not enough and what it cost.
   *
   * Reached through the relay service's PUBLIC `reservations` getter (a `PeerMap`), not through the
   * private reservation store — no cast through a private field, so a libp2p upgrade that changes
   * the internals cannot silently turn this into a no-op; it would fail to compile.
   */
  releaseRelayReservation(peerIdStr: string): boolean {
    let peerId: ReturnType<typeof peerIdFromString>;
    try {
      peerId = peerIdFromString(peerIdStr);
    } catch {
      // Same reasoning as hangUp: name it rather than letting a parse error read as a relay fault.
      return false;
    }
    const relay = (this.#libp2p.services as Record<string, unknown>)["relay"] as
      | { reservations?: { has(p: typeof peerId): boolean; delete(p: typeof peerId): unknown } }
      | undefined;
    const reservations = relay?.reservations;
    // A node with no relay service (every client node) holds no reservations to release.
    if (!reservations) return false;
    if (!reservations.has(peerId)) return false;
    reservations.delete(peerId);
    return true;
  }

  async hangUp(peerIdStr: string): Promise<void> {
    let peerId;
    try {
      peerId = peerIdFromString(peerIdStr);
    } catch {
      // NAMED, not passed through. A caller handed us something that is not a peer id; letting
      // libp2p's parse error escape would be logged as a connection problem, which is the exact
      // cause-for-symptom substitution this milestone exists to remove.
      throw {
        reason: "invalid_peer_id",
        peerId: peerIdStr,
        message: `Invalid peer ID: ${peerIdStr}`,
      };
    }
    await this.#libp2p.hangUp(peerId);
  }

  /** DOD-RELAY-KEEPALIVE-1: the connection-monitor policy this node was built with. */
  getConnectionMonitorPolicy(): ResolvedConnectionMonitorConfig {
    return this.#connectionMonitorPolicy;
  }

  /** Set once by createNode, from resolveConnectionMonitorConfig — the same object libp2p got. */
  setConnectionMonitorPolicy(policy: ResolvedConnectionMonitorConfig): void {
    this.#connectionMonitorPolicy = policy;
  }

  /** DOD-M12B-ACK-1: live stream count for one protocol on the connections to a peer. See the
   *  interface doc — this is what lets a cap-exhaustion failure name its cause. */
  countProtocolStreams(peerIdStr: string, protocolId: string): { inbound: number; outbound: number } {
    let peerId;
    try {
      peerId = peerIdFromString(peerIdStr);
    } catch {
      return { inbound: 0, outbound: 0 };
    }
    let inbound = 0;
    let outbound = 0;
    for (const conn of this.#libp2p.getConnections(peerId)) {
      for (const stream of conn.streams) {
        if (stream.protocol !== protocolId) continue;
        if (stream.direction === "inbound") inbound++;
        else outbound++;
      }
    }
    return { inbound, outbound };
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

  // A limited-connection refusal is a POLICY refusal, not a network failure —
  // do not collapse it into connection_lost. CELLO's own paths always set
  // runOnLimitedConnection, so seeing this means a protocol/handler missed it.
  if ((err instanceof Error && err.name === "LimitedConnectionError") || msg.includes("limited connection")) {
    return { reason: "limited_connection_refused", protocolId, message: msg };
  }

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
 *   - Services: identify, circuitRelayServer (service nodes / opt-in), AutoNAT, DCuTR
 *
 * NAT traversal:
 *   - autoNAT() is added to ALL nodes. On client nodes (session / standing
 *     receiver) it probes connected directory nodes for dial-back to determine
 *     dialability; on directory nodes it serves the responder role, answering
 *     dial-back requests. Protocol: /libp2p/autonat/1.0.0.
 *   - dcutr() is included on every node type BY DEFAULT (DOD-NAT-REACHABILITY-1). The
 *     protocol's inbound peer is the one that STARTS the hole-punch upgrade
 *     (@libp2p/dcutr ignores connections with direction !== 'inbound'), and the
 *     inbound peer of a relayed connection is precisely the standing receiver.
 *     ⚠️ `opts.holePunch: { enabled: false }` OMITS it (DOD-M15-RELAYONLY-1), and the sentence
 *     directly above is the reason it had to become optional: if the inbound side starts the
 *     upgrade, a node whose operator asked never to be directly reachable would hole-punch itself
 *     into exactly the direct connection they switched the setting on to avoid. Suppressing the
 *     published address does not cover this — the address a peer cannot be TOLD, a hole-punch
 *     still REVEALS.
 *   - circuitRelayServer (HOP) is a SERVICE-node capability: included when
 *     nodeType is undefined (directory, relay) or when opts.relayServer.enabled
 *     is set. Client nodes (session / standing_receiver) no longer advertise
 *     themselves as relays for strangers.
 */
/**
 * DOD-RELAY-KEEPALIVE-1: how long a keepalive ping may take before the peer is judged dead.
 *
 * libp2p's AdaptiveTimeout floors at 5 seconds (@libp2p/utils DEFAULT_MIN_TIMEOUT), which is a
 * LAN number. The ping opens a stream — a multistream-select negotiation, and on a relayed
 * connection every frame of it crosses two WAN hops — so 5 seconds is routinely missed by a link
 * that is working perfectly. Missing it once destroys the connection, because
 * `abortConnectionOnPingFailure` defaults to true.
 *
 * 30 seconds keeps the mechanism honest — a peer that is genuinely gone is still detected — while
 * giving a slow-but-alive link six times the headroom it had when the client↔relay link was dying
 * every 60-90 seconds.
 *
 * THE COST, stated because it is a trade and not free (review F5): a counterparty that vanishes
 * WITHOUT a FIN is now detected in at most pingInterval + 30s ≈ 40s, up from ≈15s. That detection
 * is the only thing that drives `counterparty_liveness` to 'gone' for a silently-dead peer, and
 * the unilateral-seal gate reads it — so the gate must tolerate a ~40s window. If it ever cannot,
 * lower the ping INTERVAL rather than this floor: the floor is what a slow WAN round trip needs,
 * the interval is how often we ask.
 *
 * Note the floor is the effective deadline in practice, not just a lower bound: no CELLO node
 * registers a ping responder, so every ping ends in UnsupportedProtocolError — which libp2p counts
 * as alive and which returns fast — so the AdaptiveTimeout's moving average never rises.
 */
export const WAN_PING_TIMEOUT_FLOOR_MS = 30_000;

/**
 * The libp2p `connectionMonitor` init this node's options resolve to.
 *
 * There is deliberately NO `enabled` field. libp2p reads `enabled: false` to switch the monitor
 * off, and this policy never does — the pings are the keepalive. A field we never produce would
 * be a knob suggesting otherwise; its absence from this type is the statement.
 */
export interface ResolvedConnectionMonitorConfig {
  pingInterval?: number;
  pingTimeout?: { minTimeout: number };
  abortConnectionOnPingFailure?: boolean;
}

/**
 * DOD-RELAY-KEEPALIVE-1: resolve the connection-monitor policy for a node.
 *
 * The monitor is NEVER disabled. Its pings are the only keepalive traffic on an otherwise idle
 * relay link, and that traffic is what keeps network-level reapers (enterprise firewalls, NAT
 * conntrack) from collecting the connection. What changes is the verdict the monitor is allowed
 * to reach: a WAN-length deadline instead of a LAN one, and — where the caller asks for it — no
 * authority to abort the connection at all.
 *
 * The abort stays ON by default. It is what surfaces a counterparty that vanished without a FIN
 * (`peer:disconnect` → `counterparty_liveness` → 'gone'), and that detection is load-bearing for
 * the unilateral-seal gate. Only a node with no liveness duty toward its peers — the relay,
 * whose client liveness is the reservation TTL's job — should turn it off.
 */
/**
 * ─── DOD-M15-IDLE-CONNS-1 — the connection posture is DECLARED HERE, not inherited ─────────────
 *
 * `createNode` passed no `connectionManager` block at all, so every one of these came from
 * libp2p's own constants. They were correct; nobody had chosen them. A minor version bump
 * re-prices what an unauthenticated peer can spend on an operator's machine, and no test in this
 * repo would go red.
 *
 * The four values below are libp2p@3.3.2's defaults, adopted deliberately rather than changed. The
 * DoD line is explicit that caps must not be guessed — *"a cap set without measurement breaks
 * REACHABILITY, the one property this milestone must not trade away"* — and there is no
 * measurement yet, because until this unit nothing reported a connection count at all. So the
 * change here is **authorship, not tuning**: pin what runs today, make it visible, and let
 * `getConnectionLimits()` supply the number a later tuning pass needs.
 */

/** Total connections before libp2p prunes. libp2p@3.3.2 `MAX_CONNECTIONS`. */
export const DECLARED_MAX_CONNECTIONS = 300;
/** Inbound connections per remote host per window before refusal. `INBOUND_CONNECTION_THRESHOLD`. */
export const DECLARED_INBOUND_CONNECTION_THRESHOLD = 5;
/** Inbound connections mid-upgrade before new ones are refused. `MAX_INCOMING_PENDING_CONNECTIONS`. */
export const DECLARED_MAX_INCOMING_PENDING = 10;
/** How long an inbound connection may sit un-upgraded. `INBOUND_UPGRADE_TIMEOUT`. */
export const DECLARED_INBOUND_UPGRADE_TIMEOUT_MS = 10_000;

/**
 * How long an inbound connection that has NEVER carried a stream may live.
 *
 * ─── THIS MEASURES "NEVER SPOKE", NOT "IS QUIET RIGHT NOW" ─────────────────────────────────────
 *
 * The first version compared `now - openedAt` and ANDed it with `streamCount === 0` at the instant
 * of the sweep — i.e. it measured connection AGE and sampled business. Review flagged that as
 * fatal on the grounds that CELLO content streams are per-message and ephemeral, so a busy session
 * would sit at zero streams almost all of the time and be reaped mid-conversation.
 *
 * **MEASURED BEFORE ACCEPTING IT, and the stated mechanism does NOT reproduce on libp2p@3.3.2.**
 * A stream closed by the dialer stays in the listener's `connection.streams` — `streamCount` was
 * still 1 after 10s (25 samples, 400ms apart), and under the reviewer's own scenario (a stream
 * every 400ms, 1000ms grace) it CLIMBED 1→8 across 3.2s and nothing was reaped. So the specific
 * claim "a busy session sits at zero streams" is false here, and the reported hang-up at t≈1200ms
 * did not occur when the scenario was re-run against that predicate.
 *
 * **The fix stays anyway, and the reason is the honest one:** the old predicate was correct only
 * BECAUSE libp2p happens to retain closed streams. That is an implementation detail of a
 * dependency, undocumented and free to change in a patch release — precisely the kind of inherited
 * behaviour the other half of this unit exists to stop relying on. `hasEverCarriedStream` is the
 * literal reading of the DoD's "authenticates to nothing" and it holds whatever libp2p does with
 * closed streams.
 */
export const IDLE_CONNECTION_GRACE_MS = 90_000;

/** How often the sweep runs. A third of the grace period, so nothing lives much past it. */
export const IDLE_CONNECTION_SWEEP_MS = 30_000;

/** What the sweep reports when it acts, or fails to. Consumed by the daemon's logger. */
export interface IdleReapEvent {
  peerId: string;
  ageMs: number;
  reason: "never_carried_a_stream" | "hangup_failed" | "sweep_failed";
  error?: string;
}

/** The connection census, emitted every sweep — the measurement the DoD line demands. */
export interface ConnectionCounts {
  total: number;
  inbound: number;
  /** Inbound connections that have not carried a stream since they opened. */
  neverSpoke: number;
  maxConnections: number;
}

/** The connection-manager block handed to libp2p, resolved once. */
export interface ResolvedConnectionLimits {
  maxConnections: number;
  inboundConnectionThreshold: number;
  maxIncomingPendingConnections: number;
  inboundUpgradeTimeout: number;
}

/**
 * Resolve the declared limits, honouring per-node overrides.
 *
 * Spreads the declared block FIRST so an override that names one key keeps the other three. An
 * override that returned only what it was given would re-inherit the rest from libp2p — this
 * unit's own defect, reintroduced by its fix.
 */
export function resolveConnectionLimits(opts: {
  connectionLimits?: Partial<ResolvedConnectionLimits>;
}): ResolvedConnectionLimits {
  return {
    maxConnections: DECLARED_MAX_CONNECTIONS,
    inboundConnectionThreshold: DECLARED_INBOUND_CONNECTION_THRESHOLD,
    maxIncomingPendingConnections: DECLARED_MAX_INCOMING_PENDING,
    inboundUpgradeTimeout: DECLARED_INBOUND_UPGRADE_TIMEOUT_MS,
    ...(opts.connectionLimits ?? {}),
  };
}

/** What the reaper needs to judge one connection. */
export interface IdleConnectionCandidate {
  /** libp2p's per-CONNECTION id. A peer may hold several; the activity bit is per connection. */
  id: string;
  peerId: string;
  direction: "inbound" | "outbound";
  streamCount: number;
  openedAt: number;
}

/**
 * Which connections should be hung up — pure, so the judgement is testable apart from the sweep.
 *
 * FOUR THINGS ARE SPARED, and each is spared for a reason that costs something real if forgotten:
 *
 *  - **Anything carrying a stream.** That is the definition of in use.
 *  - **Anything inside the grace period.** A connection is silent for a moment on every dial.
 *  - **Every INBOUND connection that has ever carried a stream** (see the grace constant). A peer
 *    that has spoken is not "authenticating to nothing", however quiet it is now.
 *  - **Every OUTBOUND connection** — as a SELECTION rule. This node chose those: the content-park
 *    deposit and pull, the restart-seal submission to a prior session's relay. Reaping one cancels
 *    our own errand to bound someone else's connection. **Note the honest bound:** `hangUp` is
 *    PEER-scoped and drops every connection to that peer, so a peer holding one idle inbound AND
 *    one live outbound connection loses both. Nothing reaches that state today (the gater denies
 *    inbound from any peer that is not the named counterparty or the reserved relay, and both are
 *    spared), but the rule is "outbound connections are never SELECTED", not "outbound connections
 *    are never closed". This project has already paid once for a comment claiming the stronger
 *    version — `session-node-manager.ts` records a sweep that hung up the content-park dials and
 *    surfaced as `relay_unavailable`, a transport label for a local decision.
 *  - **Whatever `isSpared` names.** In production: the relay this node holds a live reservation
 *    with, and the counterparty the gate currently names. A relay reservation is IDLE BY NATURE
 *    between refreshes, which is exactly the shape hunted here — a reaper without it takes an
 *    agent's inbound reachability away and reports nothing.
 */
/**
 * Fold this sweep's observation into the activity set: mark anything carrying a stream, and forget
 * connections that have gone.
 *
 * EXTRACTED so it can be attacked directly. Mutation testing showed that deleting the recording
 * left every test green, because no live test can reach the state where it matters — libp2p retains
 * closed streams, so `streamCount` does not fall back to 0 within any window a test can wait for.
 * The bit is still the thing that makes the judgement independent of that libp2p behaviour, so it
 * needs coverage that does not depend on it.
 */
export function recordStreamActivity(
  seen: Set<string>,
  connections: readonly { id: string; streamCount: number }[],
): void {
  const live = new Set(connections.map((c) => c.id));
  for (const id of seen) if (!live.has(id)) seen.delete(id);
  for (const c of connections) if (c.streamCount > 0) seen.add(c.id);
}

export function selectIdleConnections(args: {
  connections: readonly IdleConnectionCandidate[];
  now: number;
  isSpared: (peerId: string) => boolean;
  /** Has this CONNECTION carried a stream at any point since it opened? Never a candidate if so. */
  hasEverCarriedStream: (connectionId: string) => boolean;
  graceMs?: number;
}): string[] {
  const grace = args.graceMs ?? IDLE_CONNECTION_GRACE_MS;
  const doomed = args.connections
    .filter(
      (c) =>
        c.direction === "inbound" &&
        c.streamCount === 0 &&
        !args.hasEverCarriedStream(c.id) &&
        args.now - c.openedAt >= grace &&
        !args.isSpared(c.peerId),
    )
    .map((c) => c.peerId);
  // DEDUPLICATED because `hangUp` is PEER-scoped: two idle connections to one peer would otherwise
  // yield the same id twice and hang it up twice. Harmless but noisy, and it would double-count in
  // whatever the caller reports.
  return [...new Set(doomed)];
}

export function resolveConnectionMonitorConfig(opts: {
  keepAliveIntervalMs?: number;
  connectionMonitor?: { abortConnectionOnPingFailure?: boolean; pingTimeoutMinMs?: number };
}): ResolvedConnectionMonitorConfig {
  const override = opts.connectionMonitor;
  return {
    ...(opts.keepAliveIntervalMs !== undefined ? { pingInterval: opts.keepAliveIntervalMs } : {}),
    pingTimeout: { minTimeout: override?.pingTimeoutMinMs ?? WAN_PING_TIMEOUT_FLOOR_MS },
    abortConnectionOnPingFailure: override?.abortConnectionOnPingFailure ?? true,
  };
}

export async function createNode(opts: CreateNodeOptions): Promise<CelloNode> {
  // HOP relay: service nodes keep it (deployed-relay compatibility); client node
  // types must opt in explicitly via relayServer.
  const includeRelayServer = opts.relayServer?.enabled ?? opts.nodeType === undefined;
  // Same default shape as relayServer: service nodes respond, clients do not. Clients that leave
  // nodeType unset (the directory-signaling node) must opt out EXPLICITLY.
  const includeAutonatResponder = opts.autonatResponder?.enabled ?? opts.nodeType === undefined;
  const reservations = opts.relayServer?.reservations;
  // ADR-0001: generate a fresh keypair for libp2p transport identity.
  // keyProvider is intentionally NOT touched here — see SI-002.
  const transportKey = opts.transportPrivateKey
    ? await generateKeyPairFromSeed("Ed25519", opts.transportPrivateKey)
    : await generateKeyPair("Ed25519");

  // DOD-NAT-REACHABILITY-1: a circuit-relay listen entry fails at start() when its
  // relay is unreachable, and libp2p's default fault tolerance makes ANY listener
  // failure fatal. One dead relay must never kill the node (sovereign-redundancy:
  // reservations are taken with several relays precisely so one can die), so relax
  // to NO_FATAL when circuit addrs are present. CelloNodeImpl.start() restores the
  // invariant that matters: the non-circuit (TCP) listeners must have materialised,
  // else start() throws loudly — NO_FATAL must not mask a real EADDRINUSE.
  const hasCircuitListen = opts.listenAddresses.some((a) => a.includes("/p2p-circuit"));

  // Resolved ONCE and shared: what libp2p is configured with is what the node reports, by
  // construction rather than by two call sites agreeing.
  const connectionMonitorPolicy = resolveConnectionMonitorConfig(opts);
  // Same discipline, same reason: resolved ONCE and handed to both libp2p and the node.
  const connectionLimits = resolveConnectionLimits(opts);

  const libp2p = await createLibp2p({
    start: false,
    privateKey: transportKey,
    addresses: {
      listen: opts.listenAddresses,
      ...(opts.announceAddresses?.length ? { announce: opts.announceAddresses } : {}),
      // ⚠️ DOD-M15-RELAYONLY-1: THE OTHER HALF OF THE HOLE-PUNCH FIX, and without it the whole
      // control is theatre. Turning dcutr off stops us UPGRADING to a direct connection; it does
      // nothing about `identify`, which hands a peer our full listen-address set on the FIRST
      // relayed connection — LAN addresses always, and the AutoNAT-confirmed public one once it is
      // promoted. So the counterparty would simply be TOLD the address they could not reach by
      // punching.
      //
      // `announceFilter` is libp2p's own seam for this: it decides what we advertise. Under
      // relay-only we advertise circuit addresses and nothing else, which is exactly what
      // `publishableEndpoint` does for the directory — the same rule applied on the peer-to-peer
      // side, where the directory's filter has no reach.
      ...(opts.holePunch?.enabled === false
        ? { announceFilter: (addrs: Multiaddr[]): Multiaddr[] => addrs.filter((a) => a.toString().split("/").includes("p2p-circuit")) }
        : {}),
    },
    ...(hasCircuitListen ? { transportManager: { faultTolerance: FaultTolerance.NO_FATAL } } : {}),
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
      //
      // ⚠️ DOD-M15-RELAYONLY-1 made this OPTIONAL, and the reason is the sentence directly above:
      // if the inbound side starts the upgrade, then a node that must never be directly reachable
      // will hole-punch itself into exactly the direct connection its operator switched a privacy
      // setting on to avoid. Suppressing the published address does not help — the address a peer
      // cannot be TOLD, a hole-punch still REVEALS. Default stays enabled for every other caller.
      ...(opts.holePunch?.enabled === false ? {} : { dcutr: dcutr() }),
    },
    ...(opts.connectionGater ? { connectionGater: opts.connectionGater } : {}),
    // DOD-M15-IDLE-CONNS-1: declared, not inherited. Same object the node reports.
    connectionManager: connectionLimits,
    // DOD-RELAY-KEEPALIVE-1: the monitor's policy is ours now, not libp2p's defaults.
    // Keepalive pings still detect a peer that vanished without a clean close, but the deadline
    // a ping must meet is a WAN deadline rather than 5 seconds.
    connectionMonitor: connectionMonitorPolicy,
  });

  // Record the hosts this node was configured to listen on / announce.
  // deriveDialability excludes these so dialability reflects AutoNAT dial-back
  // confirmation, not configuration.
  const configuredHosts = buildConfiguredHosts(opts.listenAddresses, opts.announceAddresses);

  // Return node in STOPPED state — caller must call start()
  const expectsDirectListener =
    hasCircuitListen && opts.listenAddresses.some((a) => !a.includes("/p2p-circuit"));
  const node = new CelloNodeImpl(libp2p, opts.keyProvider, configuredHosts, expectsDirectListener, hasCircuitListen, !includeAutonatResponder);
  node.setConnectionMonitorPolicy(connectionMonitorPolicy);
  node.setConnectionLimits(connectionLimits);
  if (opts.idleConnectionReaper) {
    node.enableIdleReaper({
      graceMs: opts.idleConnectionReaper.graceMs ?? IDLE_CONNECTION_GRACE_MS,
      sweepIntervalMs: opts.idleConnectionReaper.sweepIntervalMs ?? IDLE_CONNECTION_SWEEP_MS,
      // Forwarded EXPLICITLY. The first version of this call built the config from the two numbers
      // and silently dropped both callbacks, so the daemon's logging and its connection census were
      // declared, honoured by the node, and reachable by nobody — the same shape as `wait_for_seal`
      // being declared, honoured and never forwarded by the shim.
      ...(opts.idleConnectionReaper.onReaped ? { onReaped: opts.idleConnectionReaper.onReaped } : {}),
      ...(opts.idleConnectionReaper.onObserved ? { onObserved: opts.idleConnectionReaper.onObserved } : {}),
    });
  }
  return node;
}
