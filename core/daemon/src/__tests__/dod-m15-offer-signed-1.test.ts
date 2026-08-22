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
 *      channels, not an authentication of either. The assignment's signature IS verified now
 *      (`DOD-M15-RESPONDER-VERIFY-1`), but that runs after this and, on first contact, proves only
 *      internal consistency — so one compromised directory still controls both frames here and says
 *      the same thing twice. It catches an attacker who can influence one and not the other: a
 *      replayed or stale offer, a second node injecting an offer for a session it is not brokering,
 *      a self-contradicting broken directory.
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
import { generateKeypair } from "@cello-protocol/crypto";
import { createInboundSessions, type InboundSessionDeps } from "../inbound-sessions.js";
import { TIER } from "../contacts-tier-migration.js";
import { makeSignedAssignmentFrame } from "./helpers/signed-assignment.js";
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
  /** The counterparty's trust tier. KNOWN+ earns a `session_refused` frame. */
  tier?: number;
}) {
  const { logger, events } = makeLogger();
  let inbound: ((frame: Record<string, unknown>) => void) | null = null;
  const revoked: Array<{ agent: string; session: string }> = [];
  const accepted: string[] = [];
  /** The DURABLE refusal rows — what stops parked content re-pulling forever across a restart. */
  const durable: Array<{ agent: string; session: string; reason: string }> = [];
  /** Frames this daemon sent back out. The counterparty's only view of what happened. */
  const sentFrames: Array<Record<string, unknown>> = [];

  const sessionNodeManager = {
    getOfferedDialer: () => opts.offeredDialer ?? null,
    clearOfferedDialer: () => {},
    revokeOfferedDialer: async (agent: string, session: string) => {
      revoked.push({ agent, session });
    },
    recordRefusedSession: (agent: string, session: string, reason: string) => {
      durable.push({ agent, session, reason });
    },
    getTier: () => opts.tier ?? TIER.KNOWN,
    resolveTierBound: () => 3,
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
    sendOver: async (_agent: string, frame: Record<string, unknown>) => {
      sentFrames.push(frame);
      return { ok: true };
    },
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

  // The RETURN VALUE, not discarded. `refusedSessionRequests` is the in-memory list `cello_inbox`
  // reads — the operator-facing half of Invariant 2. The first version of this file threw it away
  // and asserted only on the log, which is the belief the invariant exists to break: a review
  // deleted BOTH `recordRefusal` calls and the whole 4,057-test gate stayed green.
  const api = createInboundSessions(deps);

  /**
   * Inject a GENUINELY SIGNED `session_assignment`.
   *
   * It used to inject an all-zeros `directory_signature`, which worked only because the responder
   * did not verify. `DOD-M15-RESPONDER-VERIFY-1` made it verify, and these tests would then have
   * been refused before reaching the checks they are about — passing for the wrong reason on the
   * ACCEPTS cases and for a coincidental one on the REFUSES cases.
   *
   * `signWith` lets a test control the signer, so the pinned-key check can be exercised against a
   * key the fixture also seeds as the pin.
   */
  const inject = async (assignedDialer: string, signer: ReturnType<typeof generateKeypair>): Promise<void> => {
    const { frame } = await makeSignedAssignmentFrame({
      sessionId: SESSION_ID,
      initiatorPubkey: Buffer.from(COUNTERPARTY, "hex"),
      responderPubkey: Buffer.from(AGENT_PUBKEY, "hex"),
      initiatorSessionPeerId: assignedDialer,
      signWith: signer,
    });
    inbound?.(frame);
  };

  return {
    inject,
    injectRaw: (f: Record<string, unknown>) => inbound?.(f),
    events,
    revoked,
    accepted,
    durable,
    sentFrames,
    /** What `cello_inbox` would show this operator. */
    operatorSees: (): Array<{ reason: string; sessionIdHex: string }> =>
      (api.refusedSessionRequests.get(AGENT) ?? []) as Array<{ reason: string; sessionIdHex: string }>,
  };
}

/**
 * THE THREE SURFACES A SECURITY REFUSAL MUST REACH, asserted together.
 *
 * Invariant 2 says loud in the LOG **and** in the agent-facing response, never one instead of the
 * other — and this milestone has now had that guard go missing four separate times. Each of the
 * three below was, at review time, deletable with a fully green gate:
 *
 *   - the operator's `cello_inbox` list (in-memory)
 *   - the DURABLE refused-session row, without which content the initiator already parked for this
 *     session re-pulls forever — the 78-times-per-message loop M12-P18 closed
 *   - the `session_refused` frame, without which the counterparty sees a transport-shaped failure
 *     naming nothing that is actually wrong, and reports that CELLO is broken
 */
function expectFullyRefused(
  h: ReturnType<typeof harness>,
  reason: string,
  guidanceMatch: RegExp,
): void {
  expect(h.accepted, "nothing may be accepted after a refusal").toEqual([]);
  expect(h.revoked.length, "the gate must be re-closed, not left open to the refused peer").toBe(1);

  const inbox = h.operatorSees();
  expect(inbox.map((r) => r.reason), "the operator must see this in cello_inbox, not only in the log")
    .toContain(reason);

  expect(h.durable.map((r) => r.reason), "a durable row must exist or parked content re-pulls forever")
    .toContain(reason);

  const refusedFrame = h.sentFrames.find((f) => f["type"] === "session_refused");
  expect(refusedFrame, "a KNOWN counterparty must be told why, not left with a dead dial").toBeDefined();
  expect(refusedFrame?.["reason"]).toBe(reason);
  expect(String(refusedFrame?.["guidance"]), "the counterparty's guidance must name their own next step")
    .toMatch(guidanceMatch);
}

const settle = (): Promise<void> => new Promise((r) => setImmediate(r));

describe("DOD-M15-OFFER-SIGNED-1: the offer and the assignment must agree on the dialer", () => {
  it("REFUSES when they name different dialers, and re-closes the gate it had opened", async () => {
    // The gate was already narrowed to whoever the offer named. Refusing without re-closing would
    // leave the door open to exactly the peer just declared unauthorised (review F4).
    const h = harness({ offeredDialer: "12D3KooWAttacker" });
    await h.inject(REAL_DIALER, generateKeypair());
    await settle();

    const refused = h.events.find((e) => e.event === "session.inbound.assignment.dialer_mismatch");
    expect(refused, "a disagreement between the two frames must refuse the session").toBeDefined();
    expect(refused?.level).toBe("error");
    expectFullyRefused(h, "offer_assignment_dialer_mismatch", /start a new session/i);
  });

  it("ACCEPTS when both name the same dialer", async () => {
    const h = harness({ offeredDialer: REAL_DIALER });
    await h.inject(REAL_DIALER, generateKeypair());
    await settle();

    expect(h.events.find((e) => e.event === "session.inbound.assignment.dialer_mismatch")).toBeUndefined();
    expect(h.revoked).toEqual([]);
  });

  it("ACCEPTS when no offer was recorded — absence is not disagreement", async () => {
    // A restart between the two frames loses the record, and the in-process seams inject
    // assignments directly. Treating that as a mismatch would refuse legitimate sessions to catch
    // nothing; the assignment is the stronger document and stands alone.
    const h = harness({ offeredDialer: null });
    await h.inject(REAL_DIALER, generateKeypair());
    await settle();

    expect(h.events.find((e) => e.event === "session.inbound.assignment.dialer_mismatch")).toBeUndefined();
  });
});

describe("DOD-M15-OFFER-SIGNED-1: a counterparty's pinned identity cannot change quietly", () => {
  it("REFUSES when the assignment does not verify under the key recorded for this counterparty", async () => {
    /**
     * The one check in this path a compromised directory cannot satisfy by repeating itself: the
     * anchor is what THIS daemon wrote during an earlier session.
     *
     * And it is a VERIFICATION, not a comparison — the signature must verify under the pinned key.
     * A directory that names the right key without holding it passes a comparison and fails this.
     */
    const pinned = generateKeypair();
    const pinnedHex = Buffer.from(await pinned.getPublicKey()).toString("hex");
    const impostor = generateKeypair();

    const h = harness({ offeredDialer: REAL_DIALER, pinnedPrimary: pinnedHex });
    await h.inject(REAL_DIALER, impostor);
    await settle();

    const refused = h.events.find((e) => e.event === "session.inbound.counterparty_primary_changed");
    expect(refused, "an identity substitution must not be accepted quietly").toBeDefined();
    expect(refused?.level).toBe("error");
    // The remedy must be one that WORKS — review F2 found the printed one did not clear the pin.
    expect(String(refused?.context["guidance"])).toMatch(/out of band/i);
    expect(String(refused?.context["guidance"])).toMatch(/cello_contact_remove/);
    // And the counterparty is told the SAME remedy, since they are the one who must act on it.
    expectFullyRefused(h, "counterparty_primary_key_changed", /out of band/i);
  });

  it("ACCEPTS a session signed by the SAME key on a later session", async () => {
    const pinned = generateKeypair();
    const pinnedHex = Buffer.from(await pinned.getPublicKey()).toString("hex");

    const h = harness({ offeredDialer: REAL_DIALER, pinnedPrimary: pinnedHex });
    await h.inject(REAL_DIALER, pinned);
    await settle();

    expect(h.events.find((e) => e.event === "session.inbound.counterparty_primary_changed")).toBeUndefined();
    expect(h.revoked).toEqual([]);
  });

  it("ACCEPTS first contact, which is the stated bound of trust-on-first-use", async () => {
    // No pin ⇒ nothing independent to verify against, so the check falls back to internal
    // consistency. Worth nothing the first time, and saying so is the difference between a bound
    // and a gap.
    const h = harness({ offeredDialer: REAL_DIALER, pinnedPrimary: null });
    await h.inject(REAL_DIALER, generateKeypair());
    await settle();

    expect(h.events.find((e) => e.event === "session.inbound.counterparty_primary_changed")).toBeUndefined();
  });

  it("REFUSES a TAMPERED assignment even on first contact — a bad first pin is permanent", async () => {
    /**
     * The half of `DOD-M15-RESPONDER-VERIFY-1` that matters most on first contact. Internal
     * consistency cannot authenticate the directory, and is not claimed to — but it does catch an
     * assignment whose fields were altered after signing. Without it, a tampered first contact gets
     * PINNED, and every later session with that counterparty is then measured against a poisoned
     * anchor.
     */
    const signer = generateKeypair();
    const { frame } = await makeSignedAssignmentFrame({
      sessionId: SESSION_ID,
      initiatorPubkey: Buffer.from(COUNTERPARTY, "hex"),
      responderPubkey: Buffer.from(AGENT_PUBKEY, "hex"),
      initiatorSessionPeerId: REAL_DIALER,
      signWith: signer,
    });
    // Tamper AFTER signing — change a field the TBS covers. This tests that the BINDING holds,
    // which is stronger than feeding it noise.
    (frame["assignment"] as Record<string, unknown>)["initiator_session_peer_id"] = "12D3KooWImpostor";

    const h = harness({ offeredDialer: "12D3KooWImpostor", pinnedPrimary: null });
    h.injectRaw(frame);
    await settle();

    const refused = h.events.find((e) => e.event === "session.inbound.assignment.invalid");
    expect(refused, "a tampered assignment must not be pinned").toBeDefined();
    expect(String(refused?.context["reason"])).toBe("inbound_assignment_signature_invalid");
    expectFullyRefused(h, "inbound_assignment_invalid", /start a new session/i);
  });
});
