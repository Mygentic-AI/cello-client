/**
 * The production session-node factory, and the key stub session nodes are built with.
 *
 * A session node needs no signing key — libp2p generates its own transport keypair — but the
 * `createNode` interface requires a provider, so the stub exists to satisfy a type rather than to
 * hold a secret. That is worth saying out loud in a repository where a key provider usually does.
 *
 * Moved out of daemon.ts by 040-DAEMONROOT unit 8: it is a class, not composition, and it had simply
 * always lived at the top of the boot file. `daemon.ts` re-exports it, so every existing importer —
 * including the tests that construct one directly — is unchanged.
*/
import {
  createNode,
  // DOD-M15-IDLE-CONNS-1 — what the idle sweep reports when it acts, and its per-sweep census.
  type IdleReapEvent,
  type ConnectionCounts,
} from "@cello-protocol/transport";
import type { ISessionNodeFactory, SessionNodeConfig } from "./session-node-manager.js";
// DOD-M15-IDLE-CONNS-1 — the factory logs what the idle sweep did.
import type { Logger } from "./types.js";

// Minimal no-op KeyProvider stub for session nodes.
// Session nodes don't need signing keys — libp2p generates its own fresh
// transport keypair internally. The KeyProvider interface is required by
// createNode but is never called on session nodes.
const SESSION_NODE_KEY_STUB = {
  getPublicKey: () => Promise.resolve(new Uint8Array(32)),
  sign: (_data: Uint8Array) => Promise.resolve(new Uint8Array(64)),
};

// Production session node factory — wraps createNode from @cello-protocol/transport
export class ProductionSessionNodeFactory implements ISessionNodeFactory {
  /**
   * DOD-M15-IDLE-CONNS-1 — OPTIONAL, and optional for one reason only: this factory is constructed
   * with no arguments in four existing tests, and requiring a logger would turn them into type
   * errors for a unit that has nothing to do with them.
   *
   * The cost is stated rather than hidden: with no logger, a reaped connection is silent, which is
   * exactly the "guard nobody hears" this milestone has found four times. `startDaemon` passes one
   * — that is the production path — and the sweep only runs on nodes this factory builds as
   * receivers, so the silent case is a test-only fixture.
   */
  constructor(private readonly logger?: Logger) {}

  async createNode(config: SessionNodeConfig) {
    // DOD-NAT-REACHABILITY-1: the STANDING RECEIVER — the node that accepts every
    // inbound session — must bind a ROUTABLE interface by default. The old
    // loopback default meant a node announced 127.0.0.1 and was dialable by
    // nobody unless the operator hand-set CELLO_LISTEN_ADDR (only the EC2 demo
    // agent ever did). CELLO_LISTEN_ADDR / CELLO_ANNOUNCE_ADDRS remain as
    // overrides for publicly-hosted agents (M6 parity). Ephemeral session nodes
    // (which dial OUT and need no inbound reachability) stay on loopback.
    // DOD-M12B-SESSION-SEED-1 (case B review HIGH-1): `inboundReachable` is the REVIVED session
    // node. Every production session node reached its role by promotion and so inherited the
    // receiver's routable bind; a rebuilt one inherits nothing and would come back on loopback,
    // preserving an identity nobody can dial.
    const isReceiver = config.nodeType === "standing_receiver" || config.inboundReachable === true;
    const listenAddr = isReceiver
      ? (process.env["CELLO_LISTEN_ADDR"] ?? "/ip4/0.0.0.0/tcp/0")
      : "/ip4/127.0.0.1/tcp/0";
    const announce =
      isReceiver && process.env["CELLO_ANNOUNCE_ADDRS"]
        ? process.env["CELLO_ANNOUNCE_ADDRS"].split(",").map((s) => s.trim()).filter(Boolean)
        : undefined;
    return createNode({
      keyProvider: SESSION_NODE_KEY_STUB,
      // Circuit-relay listen entries (reservations) ride alongside the TCP
      // listener; the transport tolerates a dead relay (NO_FATAL) but still
      // fails loudly if the TCP bind itself is lost.
      listenAddresses: [listenAddr, ...(config.circuitRelayListenAddrs ?? [])],
      ...(announce ? { announceAddresses: announce } : {}),
      connectionGater: config.connectionGater,
      // DOD-M15-RELAYONLY-1: an agent that asked never to be directly reachable must not hole-punch
      // its way to a direct connection. dcutr's job is to UPGRADE a relayed connection, and the
      // INBOUND side starts that upgrade — which is precisely the standing receiver. So filtering
      // what the directory publishes is not enough on its own: the address a peer cannot be TOLD, a
      // hole-punch still REVEALS, and it happens inside libp2p after every assertion has passed.
      ...(config.relayOnly === true ? { holePunch: { enabled: false } } : {}),
      // Forward the role. After DOD-NAT-REACHABILITY-1, dcutr is on every node
      // type unless relay-only turns it off above; nodeType's remaining transport effect is the HOP
      // gate (client types never advertise circuit-relay HOP).
      nodeType: config.nodeType,
      // DOD-M12B-SESSION-SEED-1: forward the caller's transport seed when it supplied one, so a
      // rebuilt session node returns at the peer id the counterparty already holds. Omitted (rather
      // than passed as undefined) when absent, keeping createNode's "generate a fresh key" default
      // for every node that is not session-scoped.
      ...(config.transportPrivateKey ? { transportPrivateKey: config.transportPrivateKey } : {}),
      /**
       * DOD-M15-IDLE-CONNS-1 — the idle sweep is armed on the node that STARTS as a standing
       * receiver.
       *
       * **It is NOT "the standing receiver only", and an earlier version of this comment said so
       * and was false.** `acceptSession` does not build a new node: it moves this same `CelloNode`
       * from `#standingReceivers` into `#activeNodes`, so the interval keeps running after
       * promotion, against the session's own counterparty. Review measured the consequence — the
       * counterparty was hung up mid-conversation and the next send failed with `no_connection`,
       * with nothing anywhere naming the local sweep.
       *
       * That is survivable only because the spared predicate below names the counterparty. The
       * arrangement is deliberate now rather than accidental: one node, one interval, and the gate
       * decides who is off-limits as it narrows.
       */
      ...(isReceiver
        ? {
            idleConnectionReaper: {
              /**
               * C3 — THE GUARD IS HEARD. A hang-up that tells nobody is indistinguishable from the
               * thing simply not happening, and review measured what that costs: the operator's
               * next send returns `no_connection`, `session.transport.redial.unavailable` says
               * "every send parks until they re-establish", and not one word in that chain names a
               * `setInterval` on their own machine.
               *
               * WARN and CONTINUE, deliberately: this is resource bounding, not a security event.
               * Nothing is refused and no session state changes — so it is loud, and it does not
               * block (Invariant 2's own distinction).
               */
              onReaped: (e: IdleReapEvent) => {
                if (e.reason === "never_carried_a_stream") {
                  this.logger?.warn("session.node.connection.reaped", {
                    sessionId: config.sessionId,
                    peerId: e.peerId,
                    ageMs: e.ageMs,
                    observation:
                      "an inbound connection was hung up after never carrying a stream since it opened",
                    impact:
                      "no session state changed and nothing was refused; if this peer returns it must dial again",
                  });
                  return;
                }
                // A sweep that cannot do its job is a different event and must not read as one that
                // did. `hangUp`'s `invalid_peer_id` is a NAMED reason written so a malformed id is
                // not read as a connection problem — preserved here rather than flattened.
                this.logger?.error("session.node.connection.reap_failed", {
                  sessionId: config.sessionId,
                  peerId: e.peerId,
                  reason: e.reason,
                  error: e.error,
                  impact:
                    "an idle connection was NOT closed; it continues to hold a slot against the connection cap",
                });
              },
              /**
               * C4 — THE COUNT THE DoD ASKS FOR, and the reason this callback exists at all.
               *
               * The line says *"measure a healthy daemon's connection count first"*, and nothing in
               * the tree reported one — not `cello_status`, not the CLI, not the log. Exposing the
               * CAPS without the COUNT would have been a capability nothing reads, which is this
               * milestone's own "no consumer, no ship". DEBUG because it is a census on a timer,
               * not an event: it exists to be greppable when a cap is finally tuned.
               */
              onObserved: (c: ConnectionCounts) => {
                this.logger?.debug("transport.connections.observed", {
                  sessionId: config.sessionId,
                  total: c.total,
                  inbound: c.inbound,
                  neverSpoke: c.neverSpoke,
                  maxConnections: c.maxConnections,
                });
              },
            },
          }
        : {}),
    }).then((node) => {
      /**
       * SPARE WHAT REACHABILITY DEPENDS ON — two things, and the second was missing.
       *
       * **The reserved relay.** The same list `DOD-M15-FRAME-1`'s eviction sweep spares, for the
       * reason its comment gives: reservation refreshes ride those peers, and hanging one up costs
       * the agent its inbound reachability. A reservation is IDLE BY NATURE between refreshes,
       * which is exactly the shape the sweep hunts.
       *
       * **The peer the gate currently names.** `getAllowedPeerId()` is the admitted dialer before
       * promotion and the counterparty after it. Without this the sweep reaps the one peer the
       * session exists for.
       *
       * READ LIVE on every sweep, never captured: reservations are lost and retaken constantly
       * (2,675 `reservation.lost` in one daemon's log) and `#allowedPeerId` changes at offer,
       * promotion and refusal. A set frozen at build time is wrong within minutes.
       *
       * WHAT IS LEFT TO REAP, stated because a guard with no population is theatre: a peer that was
       * admitted by an offer which was then refused or expired. `closeInbound()` returns
       * `#allowedPeerId` to null, and libp2p never re-runs a gater against a connection that
       * already exists — so that peer stays attached, named by nobody, speaking nothing. That is
       * the connection this unit removes.
       */
      const gater = config.connectionGater;
      if (isReceiver && gater) {
        node.setIdleReaperSpared(
          (peerId) => gater.isAllowedOutboundPeer(peerId) || gater.getAllowedPeerId() === peerId,
        );
      }
      return node;
    });
  }
}
