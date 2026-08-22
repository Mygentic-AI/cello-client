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
  function harness(opts: { admit?: (peerId: string) => boolean } = {}) {
    const { logger, events } = makeLogger();
    const sent: Record<string, unknown>[] = [];
    const admitted: string[] = [];
    let handler: ((frame: Record<string, unknown>) => void) | null = null;

    const signaling: SignalingSeam = {
      status: "connected",
      async sendRaw(frame: unknown) {
        sent.push(frame as Record<string, unknown>);
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
        return opts.admit ? opts.admit(peerId) : true;
      },
      signaling,
      logger,
    });

    return { fire: (f: Record<string, unknown>) => handler?.(f), sent, admitted, events };
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

    // ...and only then did our address go out. Ordering is the mechanism: the initiator cannot
    // learn where to dial until the accept it triggered has been sent, so there is no interval in
    // which the advertised address is reachable by anyone else.
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
    const h = harness({ admit: () => false });
    h.fire(OFFER({ initiator_session_peer_id: "12D3KooInitiator" }));
    await new Promise((r) => setImmediate(r));

    expect(h.sent.find((f) => f["type"] === "session_offer_accept")).toBeUndefined();
    expect(h.sent.find((f) => f["type"] === "session_offer_reject")?.["reason"]).toBe("offer_named_no_dialer");
  });
});
