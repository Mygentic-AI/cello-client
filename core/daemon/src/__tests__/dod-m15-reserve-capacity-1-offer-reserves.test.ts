/**
 * DOD-M15-RESERVE-CAPACITY-1 — **THE OFFER HANDLER IS WHERE THE SLOT IS ACTUALLY TAKEN, AND IT HAD
 * NO TEST.**
 *
 * 056-SLOTDEAD found this while sweeping for dead code, which is the reason it is worth saying how.
 * The whole capacity change is "an idle agent holds nothing; the party being dialed takes ONE slot,
 * on the relay the directory named, when the offer arrives." Every existing test drove
 * `takeReservationForSession` — the seam BELOW the decision. Not one drove the offer handler, so
 * nothing exercised:
 *
 *   - reading `relay_endpoint` off the offer frame at all;
 *   - turning the relay's plain multiaddr into the `/p2p/<relay>/p2p-circuit` form it must ask on;
 *   - **re-reading the endpoint after reserving**, without which the accept advertises the address
 *     set from BEFORE the circuit existed — a reservation taken and never told to the initiator;
 *   - the ordering against `relay_only_no_reservation`, the guard that would refuse 100% of inbound
 *     offers if it sat above the reserve instead of below it.
 *
 * Worse, the dep WAS OPTIONAL (`reserveOnDemand?`), so every fixture that omitted it skipped the
 * block entirely and stayed green. A handler that never reserved at all passed the whole suite.
 * That is a hollow shape, not a gap: the tests could not have told the working version from the
 * broken one.
 *
 * ⚠️ **056-SLOTDEAD review F14 — the first version of this file DESCRIBED that hollow shape and left
 * it standing**, complete with an unused `noReserveDep` knob for reproducing it. Naming a trap is
 * not closing it. The dep is required now, so the compiler names any caller that would skip the
 * reserve, and this file is in `tsconfig.test.json` so the compiler actually reads it.
 *
 * These tests drive the handler through its deps seam — no daemon, no network, no relay.
 */
import { describe, it, expect } from "vitest";
import { wireSessionOfferHandler } from "../session-ceremony.js";
import type { Logger } from "../types.js";
import type { SignalingSeam } from "../registration-context.js";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const push = (level: string) => (event: string, context: Record<string, unknown>) => {
    events.push({ level, event, context });
  };
  return { logger: { debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error") }, events };
}

const RELAY_ID = "12D3KooWRelayOne";
const RELAY_ADDR = "/ip4/198.51.100.4/tcp/4001";
const DIRECT_ADDR = "/ip4/10.0.0.1/tcp/4001";
const CIRCUIT_ADDR = `${RELAY_ADDR}/p2p/${RELAY_ID}/p2p-circuit/p2p/12D3KooReceiver`;
const SESSION_ID = new Uint8Array([1, 2, 3, 4]);

interface HarnessOpts {
  /** What the relay says when asked. Defaults to granting. */
  grant?: boolean;
  /** What the offer frame carries as `relay_endpoint`. */
  relayEndpoint?: unknown;
  relayOnly?: boolean;
  /** Addresses the receiver reports BEFORE any reservation. */
  addrsBefore?: string[];
}

function harness(opts: HarnessOpts = {}) {
  const { logger, events } = makeLogger();
  const sent: Record<string, unknown>[] = [];
  const asked: Array<{ circuitAddr: string; sessionIdHex: string }> = [];
  /**
   * The ORDER of every observable act. Asserting two arrays are non-empty would pass for a handler
   * that advertised its address first and reserved afterwards — which is the version that tells the
   * initiator to dial an address the agent does not yet have.
   */
  const sequence: string[] = [];
  let granted = false;
  let handler: ((frame: Record<string, unknown>) => void) | null = null;

  const signaling: SignalingSeam = {
    status: "connected",
    async sendRaw(frame: unknown) {
      const f = frame as Record<string, unknown>;
      sent.push(f);
      sequence.push(`sent:${String(f["type"])}`);
      return { ok: true as const };
    },
    registerInboundHandler(h) { handler = h; return () => {}; },
  };

  wireSessionOfferHandler({
    agentName: "Responder",
    /**
     * The real thing this models: the receiver announces the circuit only AFTER the reserve
     * succeeds. A stub that returned the same addresses both times could not tell a handler that
     * re-reads from one that does not — and re-reading is the step under test.
     */
    getStandingReceiverEndpoint: () => ({
      peerId: "12D3KooReceiver",
      addrs: granted ? [...(opts.addrsBefore ?? [DIRECT_ADDR]), CIRCUIT_ADDR] : [...(opts.addrsBefore ?? [DIRECT_ADDR])],
    }),
    admitOfferedDialer: (peerId) => {
      sequence.push(`narrowed:${peerId}`);
      return peerId === "" ? "no_peer_named" : "narrowed";
    },
    ...(opts.relayOnly === undefined ? {} : { isRelayOnly: () => opts.relayOnly! }),
    reserveOnDemand: async (circuitAddr: string, sessionIdHex: string) => {
      asked.push({ circuitAddr, sessionIdHex });
      sequence.push(`reserved:${circuitAddr}`);
      granted = opts.grant ?? true;
      return granted;
    },
    signaling,
    logger,
  });

  const frame: Record<string, unknown> = {
    type: "session_offer",
    session_id: SESSION_ID,
    initiator_session_peer_id: "12D3KooInitiator",
  };
  const ep = opts.relayEndpoint === undefined
    ? { peer_id: RELAY_ID, multiaddrs: [RELAY_ADDR] }
    : opts.relayEndpoint;
  if (ep !== null) frame["relay_endpoint"] = ep;

  return {
    async fire() {
      handler?.(frame);
      // The handler runs its body in a detached async IIFE; yield until it has settled.
      for (let i = 0; i < 20; i += 1) await Promise.resolve();
    },
    sent, asked, sequence, events,
  };
}

describe("DOD-M15-RESERVE-CAPACITY-1: an inbound offer takes ONE slot, on the relay the directory named", () => {
  it("★★★ asks the OFFERED relay exactly once, in the /p2p-circuit form, before answering", async () => {
    const h = harness();
    await h.fire();

    expect(h.asked.length, "one offer, one reservation — this is the capacity equation itself").toBe(1);
    expect(h.asked[0]!.circuitAddr).toBe(`${RELAY_ADDR}/p2p/${RELAY_ID}/p2p-circuit`);
    // The relay checks an assignment naming the relay the DIRECTORY picked. Asking a relay we chose
    // ourselves would hold a slot the assignment will not route through.
    expect(h.asked[0]!.circuitAddr).toContain(RELAY_ID);
    expect(
      h.sequence.indexOf(`reserved:${RELAY_ADDR}/p2p/${RELAY_ID}/p2p-circuit`),
      "reserve BEFORE the accept — an accept sent first advertises addresses from before the circuit existed",
    ).toBeLessThan(h.sequence.indexOf("sent:session_offer_accept"));
    /**
     * ⚠️ **THE SESSION ID FORMAT IS LOAD-BEARING AND WAS UNASSERTED — review F13.** The harness
     * recorded this value and nothing checked it, so changing the encoding (base64, uppercase hex,
     * anything) left every test in this file green.
     *
     * It is not a label. It keys the abandoned-offer release timer, whose only guard is
     * `sessionIsLive(agentName, sessionIdHex)` — a lookup in `activeNodes`, which is keyed with
     * `Buffer.from(assignment.session_id).toString("hex")` by the path that creates the session. Two
     * encodings of the same id therefore never match, the guard misses every time, and the timer
     * releases the circuit out from under a conversation that is running. Lowercase hex of the raw
     * frame bytes, and it has to stay that.
     */
    expect(h.asked[0]!.sessionIdHex).toBe(Buffer.from(SESSION_ID).toString("hex"));
  });

  it("★★★ the accept advertises the circuit the reserve just took — the endpoint is RE-READ", async () => {
    const h = harness();
    await h.fire();

    const accept = h.sent.find((f) => f["type"] === "session_offer_accept");
    expect(accept, "the offer must be answered").toBeDefined();
    expect(
      accept!["counterparty_session_addrs"],
      "the whole point of reserving at offer time is that the initiator is told where to dial. A " +
        "handler that captured the endpoint before reserving takes a slot nobody is told about, " +
        "and the counterparty behind NAT cannot reach this agent for the session it just accepted",
    ).toContain(CIRCUIT_ADDR);
  });

  it("a relay that REFUSES is not fatal — the agent answers with what it has", async () => {
    const h = harness({ grant: false });
    await h.fire();

    expect(h.asked.length).toBe(1);
    const accept = h.sent.find((f) => f["type"] === "session_offer_accept");
    expect(accept, "without relay-only, a direct-dialable agent is still perfectly reachable").toBeDefined();
    expect(accept!["counterparty_session_addrs"]).toEqual([DIRECT_ADDR]);
    const resv = h.events.find((e) => e.event === "session.offer.reservation");
    expect(resv?.context["granted"]).toBe(false);
  });

  it("★★★ RELAY-ONLY: a refused relay refuses the OFFER — and a granted one does not", async () => {
    /**
     * The guard sits BELOW the reserve on purpose. Above it, an idle agent — which holds nothing by
     * design — would fail this check on every single inbound offer, taking the control that stops a
     * session revealing the operator's IP to a 100% refusal rate for exactly the operators who
     * switched it on.
     */
    const refused = harness({ grant: false, relayOnly: true, addrsBefore: [] });
    await refused.fire();
    expect(refused.sent.find((f) => f["type"] === "session_offer_accept")).toBeUndefined();
    const reject = refused.sent.find((f) => f["type"] === "session_offer_reject");
    expect(reject?.["reason"]).toBe("relay_only_no_reservation");

    const ok = harness({ grant: true, relayOnly: true, addrsBefore: [] });
    await ok.fire();
    expect(
      ok.sent.find((f) => f["type"] === "session_offer_accept"),
      "relay-only plus a granted circuit is the SUPPORTED case; refusing it would mean the control " +
        "never lets a session through at all",
    ).toBeDefined();
    expect(ok.sent.find((f) => f["type"] === "session_offer_reject")).toBeUndefined();
  });

  it("an offer that names NO relay is answered without asking anyone — the un-deployed directory", async () => {
    // The directory only started putting `relay_endpoint` on the offer in this same unit. Against a
    // fleet that has not rolled yet, the agent must degrade to its direct address rather than
    // inventing a relay or refusing the call.
    const h = harness({ relayEndpoint: null });
    await h.fire();

    expect(h.asked.length).toBe(0);
    const accept = h.sent.find((f) => f["type"] === "session_offer_accept");
    expect(accept!["counterparty_session_addrs"]).toEqual([DIRECT_ADDR]);
  });

  it("a malformed relay_endpoint asks nobody rather than asking a garbage address", async () => {
    for (const bad of [
      { peer_id: RELAY_ID, multiaddrs: [] },
      { peer_id: 42, multiaddrs: [RELAY_ADDR] },
      { multiaddrs: [RELAY_ADDR] },
      "not-an-object",
    ]) {
      const h = harness({ relayEndpoint: bad });
      await h.fire();
      expect(h.asked.length, `relay_endpoint ${JSON.stringify(bad)} must not produce an ask`).toBe(0);
      expect(h.sent.find((f) => f["type"] === "session_offer_accept")).toBeDefined();
    }
  });

  it("a relay address that ALREADY names its peer is not given a second /p2p/ segment", async () => {
    const h = harness({ relayEndpoint: { peer_id: RELAY_ID, multiaddrs: [`${RELAY_ADDR}/p2p/${RELAY_ID}`] } });
    await h.fire();

    expect(h.asked[0]!.circuitAddr).toBe(`${RELAY_ADDR}/p2p/${RELAY_ID}/p2p-circuit`);
    expect(
      h.asked[0]!.circuitAddr.split("/p2p/").length - 1,
      "a doubled /p2p/ segment is not a dialable multiaddr, and the relay would simply never answer",
    ).toBe(1);
  });
});
