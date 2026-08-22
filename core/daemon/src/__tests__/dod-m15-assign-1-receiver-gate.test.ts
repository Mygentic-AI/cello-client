/**
 * DOD-M15-ASSIGN-1 clause (b) — the standing receiver refuses any dialer not named by a live
 * session offer.
 *
 * The defect these tests pin: a standing receiver was built with `allowedPeerId: null`, and the
 * gater read null as "allow everyone". Every agent that came online was therefore dialable by any
 * peer on the network, and because libp2p never re-runs a gater against a connection that already
 * exists, a stranger who attached during that window survived promotion into the session.
 *
 * Two halves, and BOTH are load-bearing:
 *   (1) null admits nobody inbound — the door is shut while unclaimed;
 *   (2) the offer handler narrows the gate to the offered dialer BEFORE it advertises this agent's
 *       address, which is what keeps (1) from shutting out the legitimate initiator too.
 *
 * Written RED-first per SPARC Phase R. Each test targets ONE clause: reverting that clause turns
 * exactly this test red and leaves its siblings green.
 */

import { describe, it, expect } from "vitest";
import type { PeerId, MultiaddrConnection } from "@libp2p/interface";
import { SessionConnectionGater } from "../session-connection-gater.js";
import { wireSessionOfferHandler } from "../session-ceremony.js";
import type { Logger } from "../types.js";
import type { SignalingSeam } from "../registration-context.js";

interface LogEvent {
  level: string;
  event: string;
  context: Record<string, unknown>;
}

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const push = (level: string) => (event: string, context: Record<string, unknown>) => {
    events.push({ level, event, context });
  };
  return {
    logger: { debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error") },
    events,
  };
}

/**
 * The gater identifies peers by `toString()` alone and performs no crypto, so the house
 * `toString`-only stand-in (session-node-manager.test.ts AC-016) is the whole surface it touches.
 */
function peer(label: string): PeerId {
  return { toString: () => `12D3Koo${label}` } as PeerId;
}

const FAKE_CONN = {} as MultiaddrConnection;

describe("DOD-M15-ASSIGN-1 (b) — an unclaimed standing receiver admits nobody", () => {
  it("DENIES an inbound dial when no session has named a peer", () => {
    const { logger, events } = makeLogger();
    const gater = new SessionConnectionGater({ sessionId: "sr-unclaimed", allowedPeerId: null, logger });
    const stranger = peer("Stranger");

    // The pre-fix behaviour returned false here, admitting the stranger through Noise to the muxer.
    expect(gater.denyInboundEncryptedConnection(stranger, FAKE_CONN)).toBe(true);

    const rejected = events.find((e) => e.event === "session.node.connection.rejected");
    expect(rejected?.level).toBe("warn");
    expect(rejected?.context["attemptedPeerId"]).toBe(stranger.toString());
    // Fails LOUDLY: the operator is told what was refused and that it learned nothing.
    expect(String(rejected?.context["impact"])).toContain("no session has claimed");
  });

  it("still ALLOWS the receiver's own outbound errands while unclaimed", () => {
    // The receiver doubles as the daemon's general-purpose dialer for the content-park
    // deposit/pull against the relay. Those dials are this agent choosing where to go; INV-5
    // governs who may come IN. Denying them would cost message parking to close a door nobody
    // was standing at.
    const { logger } = makeLogger();
    const gater = new SessionConnectionGater({ sessionId: "sr-unclaimed", allowedPeerId: null, logger });
    const relay = peer("Relay");

    expect(gater.denyOutboundEncryptedConnection(relay, FAKE_CONN)).toBe(false);
  });

  it("STILL allows outbound errands after an offer has named an inbound dialer (review F2)", () => {
    // The regression the first version of this unit shipped. The outbound carve-out was keyed off
    // `#allowedPeerId === null`, so the moment an offer narrowed the inbound gate, the receiver —
    // still the daemon's general-purpose dialer, since no assignment exists yet — lost the right to
    // dial anything but that one peer and its reservation relays.
    //
    // What that cost: the content-park deposit/pull and the restart-seal submission both dial
    // relays chosen per errand, including one persisted from an EARLIER session. So an agent that
    // merely RECEIVED an offer would quietly stop being able to submit a seal, surfacing as
    // `relay_unavailable` — a transport label for a local gater decision.
    const { logger } = makeLogger();
    const gater = new SessionConnectionGater({ sessionId: "sr-offered", allowedPeerId: null, logger });

    gater.admitInboundPeer(peer("Initiator").toString());

    const unrelatedRelay = peer("ParkRelay");
    expect(
      gater.denyOutboundEncryptedConnection(unrelatedRelay, FAKE_CONN),
      "narrowing WHO MAY DIAL IN must not revoke this node's own right to dial out",
    ).toBe(false);
    // ...and the inbound narrowing is real, not traded away for it.
    expect(gater.denyInboundEncryptedConnection(peer("Stranger"), FAKE_CONN)).toBe(true);
  });

  it("CLOSES outbound latitude once the node is promoted into a session", () => {
    // Promotion is the point at which this stops being a general-purpose dialer. From here it may
    // reach its counterparty and the relays explicitly authorized by the assignment, nothing else.
    const { logger } = makeLogger();
    const gater = new SessionConnectionGater({ sessionId: "sr-promoted", allowedPeerId: null, logger });

    gater.setAllowedPeer(peer("Counterparty").toString());

    expect(gater.denyOutboundEncryptedConnection(peer("ParkRelay"), FAKE_CONN)).toBe(true);
    expect(gater.denyOutboundEncryptedConnection(peer("Counterparty"), FAKE_CONN)).toBe(false);
  });

  it("admits a reservation relay dialling back, without logging it as a stranger (review F7)", () => {
    // The standing receiver runs the AutoNAT client: it asks its reservation relays to dial its
    // observed address so it can learn whether it is publicly reachable. That dial-back arrives
    // INBOUND from a peer already on the outbound allowlist.
    //
    // Refusing it cost more than noise. AutoNAT answers repeated dial failures by REMOVING the
    // observed address, so the agent's own public address never becomes verified and never reaches
    // the address list shipped in `session_offer_accept`. And it logged `connection.rejected` every
    // probe cycle on the one line that is supposed to mean a stranger tried an unclaimed receiver —
    // a signal that fires on the normal case is not a signal.
    const { logger, events } = makeLogger();
    const gater = new SessionConnectionGater({ sessionId: "sr-autonat", allowedPeerId: null, logger });
    const relay = peer("ReservationRelay");
    gater.setAllowedOutboundPeer(relay.toString());

    expect(gater.denyInboundEncryptedConnection(relay, FAKE_CONN)).toBe(false);
    expect(
      events.find((e) => e.event === "session.node.connection.rejected"),
      "our own relay answering a probe we started is not a rejection worth reporting",
    ).toBeUndefined();
  });

  it("admits the named peer, and only that peer, once a session claims the receiver", () => {
    const { logger } = makeLogger();
    const gater = new SessionConnectionGater({ sessionId: "sr-claimed", allowedPeerId: null, logger });
    const initiator = peer("Initiator");
    const stranger = peer("Stranger");

    gater.setAllowedPeer(initiator.toString());

    expect(gater.denyInboundEncryptedConnection(initiator, FAKE_CONN)).toBe(false);
    expect(gater.denyInboundEncryptedConnection(stranger, FAKE_CONN)).toBe(true);
  });
});

describe("DOD-M15-ASSIGN-1 (b) — the offer narrows the gate before advertising the address", () => {
  /** Drives the offer handler directly through its deps seam — no daemon, no network. */
  function harness(opts: { admit?: (peerId: string) => "narrowed" | "no_receiver" | "no_peer_named" } = {}) {
    const { logger, events } = makeLogger();
    const sent: Record<string, unknown>[] = [];
    const admitted: string[] = [];
    /**
     * Every observable act, in the order it happened. The ordering IS the mechanism this unit
     * claims, so it has to be asserted rather than inferred from two separate arrays both being
     * non-empty — a handler that published the address first and narrowed afterwards would satisfy
     * that and reopen exactly the window the unit closes.
     */
    const sequence: string[] = [];
    let handler: ((frame: Record<string, unknown>) => void) | null = null;

    const signaling: SignalingSeam = {
      status: "connected",
      async sendRaw(frame: unknown) {
        const f = frame as Record<string, unknown>;
        sent.push(f);
        sequence.push(`sent:${String(f["type"])}`);
        return { ok: true as const };
      },
      registerInboundHandler(h) {
        handler = h;
        return () => {};
      },
    };

    wireSessionOfferHandler({
      agentName: "Responder",
      getStandingReceiverEndpoint: () => ({ peerId: "12D3KooReceiver", addrs: ["/ip4/10.0.0.1/tcp/4001"] }),
      admitOfferedDialer: (peerId) => {
        admitted.push(peerId);
        sequence.push(`narrowed:${peerId}`);
        if (opts.admit) return opts.admit(peerId);
        // Faithful to the real `admitOfferedDialer`, which owns the empty-peer-id decision: the
        // caller no longer pre-checks it, so a fake that narrowed for "" would let the handler
        // publish an address behind a gate open to nobody and the test would pass on a bug.
        return peerId === "" ? "no_peer_named" : "narrowed";
      },
      signaling,
      logger,
    });

    return { fire: (f: Record<string, unknown>) => handler?.(f), sent, admitted, sequence, events };
  }

  const OFFER = (extra: Record<string, unknown> = {}) => ({
    type: "session_offer",
    session_id: new Uint8Array(16).fill(7),
    ...extra,
  });

  it("opens the gate to the offered dialer BEFORE the accept publishes our address", async () => {
    const h = harness();
    h.fire(OFFER({ initiator_session_peer_id: "12D3KooInitiator" }));
    await new Promise((r) => setImmediate(r));

    // The gate was narrowed to exactly the peer the directory named...
    expect(h.admitted).toEqual(["12D3KooInitiator"]);

    // ...and only then did our address go out. ASSERTED AS A SEQUENCE, not as two facts that both
    // happened: the initiator cannot learn where to dial until the accept it triggered has been
    // sent, so narrowing first is what leaves no interval in which the advertised address is
    // reachable by anyone else. Reverse these two lines in the handler and this is the test that
    // notices.
    expect(h.sequence).toEqual(["narrowed:12D3KooInitiator", "sent:session_offer_accept"]);

    const accept = h.sent.find((f) => f["type"] === "session_offer_accept");
    expect(accept?.["counterparty_session_peer_id"]).toBe("12D3KooReceiver");
  });

  it("REFUSES the offer, and advertises nothing, when it names no dialer", async () => {
    const h = harness();
    h.fire(OFFER({ initiator_session_peer_id: "" }));
    await new Promise((r) => setImmediate(r));

    // Advertising anyway would be the worse failure: the initiator would dial an address whose
    // gate refuses them, and the session would die at the transport with nobody able to say why.
    expect(h.sent.find((f) => f["type"] === "session_offer_accept")).toBeUndefined();

    const reject = h.sent.find((f) => f["type"] === "session_offer_reject");
    expect(reject?.["reason"]).toBe("offer_named_no_dialer");

    const abort = h.events.find((e) => e.event === "session.offer.abort" && e.context["reason"] === "offer_named_no_dialer");
    expect(abort?.level).toBe("warn");
    // Loud AND actionable — the warning carries the consequence and what to do next.
    expect(String(abort?.context["impact"])).toContain("did not say who would dial");
    expect(String(abort?.context["guidance"])).toContain("retry");
  });

  it("REFUSES the offer when there is no receiver to narrow", async () => {
    // admitOfferedDialer returning false means the gate was NOT narrowed. Serving the session
    // anyway would advertise an address behind a door open to nobody (or, before the fix, to
    // everyone). Neither is a session worth establishing.
    const h = harness({ admit: () => "no_receiver" });
    h.fire(OFFER({ initiator_session_peer_id: "12D3KooInitiator" }));
    await new Promise((r) => setImmediate(r));

    expect(h.sent.find((f) => f["type"] === "session_offer_accept")).toBeUndefined();
    // NAMED FOR WHAT IT IS (review F6). This branch used to report `offer_named_no_dialer` — the
    // directory's fault — when the truth was that this agent had no receiver of its own, and the
    // guidance sent the operator to go look at the directory. A local problem wearing a remote
    // label is the shape that costs days.
    expect(h.sent.find((f) => f["type"] === "session_offer_reject")?.["reason"]).toBe("standing_receiver_unavailable");
    const abort = h.events.find((e) => e.event === "session.offer.abort" && e.context["reason"] === "standing_receiver_unavailable");
    expect(String(abort?.context["guidance"])).toContain("cello_start_agent");
  });
});
