/**
 * DOD-M15-OFFER-SIGNED-1 — the two inbound refusals, exercised through the REAL handler.
 *
 * ─── What this unit does and does not do ───────────────────────────────────────────────────────
 *
 * `DOD-M15-ASSIGN-1` narrows the standing receiver's gate to the peer the directory's `session_offer`
 * names. That frame carries **no signature**, and Design Decision 2 says the socket is *"gated on
 * the assignment"*. The offer stands in for it only because it is the one frame that arrives before
 * the initiator can know where to dial.
 *
 * Two checks land on the assignment:
 *
 *   1. **Offer vs assignment agree on the dialer.** This is a CONSISTENCY check between two
 *      channels, not an authentication of either — the responder does not verify the assignment's
 *      signature (`session.inbound.assignment.unverified`, deferred to SESSION-004), so one
 *      compromised directory controls both frames and simply says the same thing twice. It catches
 *      an attacker who can influence one and not the other: a replayed or stale offer, a second node
 *      injecting an offer for a session it is not brokering, a self-contradicting broken directory.
 *      **It does not close this DoD line.**
 *
 *   2. **The counterparty's pinned threshold key has not changed.** This one a directory cannot
 *      satisfy by repeating itself, because the anchor is what THIS daemon recorded during an
 *      earlier session. Trust on first use: worth nothing the first time, hardening every session
 *      after.
 *
 * ─── Why these drive `createInboundSessions` and not a local copy of the predicate ─────────────
 *
 * The first version of this file tested two helper functions it had defined ITSELF, importing
 * nothing from the files the unit changed. All eight tests passed with the production checks fully
 * deleted, and the whole file ran in 1 ms. I justified it as avoiding a two-daemon harness — and the
 * counter-example was in the same milestone: `dod-m15-assign-1-wiring.test.ts` drives the real
 * `createOutboundSessions` over a fake deps object. `createInboundSessions` takes the same shape,
 * and `sharedSignaling` is the seam that hands frames to the real handler.
 *
 * That was the THIRD hollow test on this branch. The rule earned: a test that imports nothing from
 * the file it is named for is testing its own arithmetic.
 */

import { describe, it, expect } from "vitest";
import { createInboundSessions, type InboundSessionDeps } from "../inbound-sessions.js";
import type { Logger } from "../types.js";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const push = (level: string) => (event: string, context?: Record<string, unknown>) => {
    events.push({ level, event, context: context ?? {} });
  };
  return {
    logger: { debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error") },
    events,
  };
}

const AGENT = "alice";
const AGENT_PUBKEY = "bb".repeat(32);
const COUNTERPARTY = "aa".repeat(32);
const SESSION_ID = new Uint8Array(16).fill(9);
const REAL_DIALER = "12D3KooWRealInitiator";

/**
 * Build the real inbound handler over fakes, and return the levers a test needs: the frame injector,
 * the captured log, and what the manager was asked.
 */
function harness(opts: {
  offeredDialer?: string | null;
  pinnedPrimary?: string | null;
}) {
  const { logger, events } = makeLogger();
  let inbound: ((frame: Record<string, unknown>) => void) | null = null;
  const revoked: Array<{ agent: string; session: string }> = [];
  const accepted: string[] = [];

  const sessionNodeManager = {
    getOfferedDialer: () => opts.offeredDialer ?? null,
    clearOfferedDialer: () => {},
    revokeOfferedDialer: async (agent: string, session: string) => {
      revoked.push({ agent, session });
    },
    getPinnedCounterpartyPrimary: () => opts.pinnedPrimary ?? null,
    getSessionRecord: () => undefined,
    // Reaching this means neither refusal fired — the session was accepted.
    ensureStandingReceiverForAgent: (agentName: string) => {
      accepted.push(agentName);
    },
    getStandingReceiverReady: () => true,
  };

  const deps = {
    logger,
    sessionNodeManager,
    agents: [{ name: AGENT, pubkey: AGENT_PUBKEY }],
    sharedSignaling: {
      registerInboundHandler(h: (frame: Record<string, unknown>) => void) {
        inbound = h;
        return () => {};
      },
    },
    sendOver: async () => ({ ok: true }),
    isExplicitlyOffline: () => false,
    getConnState: () => undefined,
    resolveCurrentAgent: () => AGENT,
    NO_CURRENT_AGENT_RESPONSE: {},
    getKeyProvider: () => undefined,
    handleInboundSealInterruptedRequest: async () => {},
    reapDeadHalfOpenSessions: () => {},
    sendAwayResponse: async () => {},
    dispatchSessionStateChangedWithTelegram: () => {},
    sendTelegramDoorbell: async () => {},
    isDeliveryOpenToAgent: () => false,
  } as unknown as InboundSessionDeps;

  createInboundSessions(deps);

  /** Inject a `session_assignment` naming `assignedDialer` and `signerPubkey`. */
  const inject = (assignedDialer: string, signerPubkey: string): void => {
    inbound?.({
      type: "session_assignment",
      assignment: {
        session_id: SESSION_ID,
        participant_a: { pubkey: Buffer.from(COUNTERPARTY, "hex"), peer_id: "", multiaddrs: [] },
        participant_b: { pubkey: Buffer.from(AGENT_PUBKEY, "hex"), peer_id: "", multiaddrs: [] },
        relay_endpoint: { peer_id: "", multiaddrs: [] },
        directory_endpoint: { peer_id: "", multiaddrs: [] },
        session_timestamp: 1_700_000_000_000,
        directory_pubkey: new Uint8Array(32),
        directory_signature: new Uint8Array(64),
        signature_type: "frost",
        signer_pubkey: Buffer.from(signerPubkey, "hex"),
        initiator_session_peer_id: assignedDialer,
        initiator_session_addrs: ["/ip4/127.0.0.1/tcp/1"],
        counterparty_session_peer_id: "12D3KooWReceiver",
        counterparty_session_addrs: ["/ip4/127.0.0.1/tcp/2"],
        transport_mode: "relay",
      },
    });
  };

  return { inject, events, revoked, accepted };
}

const settle = (): Promise<void> => new Promise((r) => setImmediate(r));

describe("DOD-M15-OFFER-SIGNED-1: the offer and the assignment must agree on the dialer", () => {
  it("REFUSES when they name different dialers, and re-closes the gate it had opened", async () => {
    // The gate was already narrowed to whoever the offer named. Refusing without re-closing would
    // leave the door open to exactly the peer just declared unauthorised (review F4).
    const h = harness({ offeredDialer: "12D3KooWAttacker" });
    h.inject(REAL_DIALER, COUNTERPARTY);
    await settle();

    const refused = h.events.find((e) => e.event === "session.inbound.assignment.dialer_mismatch");
    expect(refused, "a disagreement between the two frames must refuse the session").toBeDefined();
    expect(refused?.level).toBe("error");
    expect(h.accepted, "nothing may be accepted after a refusal").toEqual([]);
    expect(h.revoked.length, "the gate must be re-closed, not left open to the refused peer").toBe(1);
  });

  it("ACCEPTS when both name the same dialer", async () => {
    const h = harness({ offeredDialer: REAL_DIALER });
    h.inject(REAL_DIALER, COUNTERPARTY);
    await settle();

    expect(h.events.find((e) => e.event === "session.inbound.assignment.dialer_mismatch")).toBeUndefined();
    expect(h.revoked).toEqual([]);
  });

  it("ACCEPTS when no offer was recorded — absence is not disagreement", async () => {
    // A restart between the two frames loses the record, and the in-process seams inject
    // assignments directly. Treating that as a mismatch would refuse legitimate sessions to catch
    // nothing; the assignment is the stronger document and stands alone.
    const h = harness({ offeredDialer: null });
    h.inject(REAL_DIALER, COUNTERPARTY);
    await settle();

    expect(h.events.find((e) => e.event === "session.inbound.assignment.dialer_mismatch")).toBeUndefined();
  });
});

describe("DOD-M15-OFFER-SIGNED-1: a counterparty's pinned identity cannot change quietly", () => {
  it("REFUSES when the directory names a different threshold key for a known counterparty", async () => {
    // The one check in this path a compromised directory cannot satisfy by repeating itself: the
    // anchor is what THIS daemon wrote during an earlier session.
    const h = harness({ offeredDialer: REAL_DIALER, pinnedPrimary: "cc".repeat(32) });
    h.inject(REAL_DIALER, "dd".repeat(32));
    await settle();

    const refused = h.events.find((e) => e.event === "session.inbound.counterparty_primary_changed");
    expect(refused, "an identity substitution must not be accepted quietly").toBeDefined();
    expect(refused?.level).toBe("error");
    // The remedy has to be one that WORKS — review F2 found the printed one did not clear the pin.
    expect(String(refused?.context["guidance"])).toMatch(/out of band/i);
    expect(h.accepted).toEqual([]);
    expect(h.revoked.length, "the gate must be re-closed here too").toBe(1);
  });

  it("ACCEPTS the same key on a later session — the ordinary repeat-counterparty case", async () => {
    const h = harness({ offeredDialer: REAL_DIALER, pinnedPrimary: "cc".repeat(32) });
    h.inject(REAL_DIALER, "cc".repeat(32));
    await settle();

    expect(h.events.find((e) => e.event === "session.inbound.counterparty_primary_changed")).toBeUndefined();
  });

  it("ACCEPTS first contact, which is the stated bound of trust-on-first-use", async () => {
    // Worth nothing the first time, and saying so is the difference between a bound and a gap.
    const h = harness({ offeredDialer: REAL_DIALER, pinnedPrimary: null });
    h.inject(REAL_DIALER, "dd".repeat(32));
    await settle();

    expect(h.events.find((e) => e.event === "session.inbound.counterparty_primary_changed")).toBeUndefined();
  });
});
