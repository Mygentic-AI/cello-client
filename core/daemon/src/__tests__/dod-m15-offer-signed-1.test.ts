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
    ensureStandingReceiverForAgent: async (agentName: string) => {
      accepted.push(agentName);
    },
    getStandingReceiverReady: () => true,
    /**
     * THE ACCEPT PATH, stubbed so acceptance is OBSERVABLE.
     *
     * Without these the accept threw `checkUnknownSenderAcceptanceBound is not a function` and the
     * session was never enqueued — which the three "ACCEPTS …" tests above did not notice, because
     * they only assert that a refusal event is ABSENT. An accept that dies of a missing stub also
     * has no refusal event, so they were passing on the absence of a thing that could not happen.
     * `enqueued()` is the positive assertion they were missing.
     */
    checkUnknownSenderAcceptanceBound: () => ({ ok: true as const }),
    sessionsConsumingCap: () => 0,
    capDiagnostics: () => ({}),
    recordCounterpartyPrimary: () => {},
    recordOfferedMoniker: () => {},
    addContact: () => {},
    // The responder records the session's chain starting point immediately before accepting it.
    recordSessionGenesis: () => {},
    acceptSession: async () => ({ ok: true }),
    resolveAgentId: () => "agent-id",
    // Throws on purpose: the trust-signal projection catches it and logs signal.projection.failed,
    // which is the documented degraded path. A stub returning a fake DB would be testing the stub.
    getDb: () => { throw new Error("no db in this harness"); },
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
    /** The event queued for `cello_await_session` — what the AGENT actually receives. */
    enqueued: (): { verification?: string } | undefined =>
      (api.inboundSessionQueues.get(AGENT) ?? [])[0] as { verification?: string } | undefined,
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
    // POSITIVE, not merely the absence of a refusal — see the note on the accept-path stubs.
    expect(h.enqueued(), "the session must actually reach the agent").toBeDefined();
  });

  it("ACCEPTS when no offer was recorded — absence is not disagreement", async () => {
    // A restart between the two frames loses the record, and the in-process seams inject
    // assignments directly. Treating that as a mismatch would refuse legitimate sessions to catch
    // nothing; the assignment is the stronger document and stands alone.
    const h = harness({ offeredDialer: null });
    await h.inject(REAL_DIALER, generateKeypair());
    await settle();

    expect(h.events.find((e) => e.event === "session.inbound.assignment.dialer_mismatch")).toBeUndefined();
    expect(h.enqueued(), "the session must actually reach the agent").toBeDefined();
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
    expect(h.enqueued(), "the session must actually reach the agent").toBeDefined();
  });

  it("TELLS THE AGENT it is first contact — the bound is worthless if only the log knows", async () => {
    /**
     * Review F6. The weaker mode was documented in a source comment and one log line, so
     * `cello_inbox` and `cello_await_session` handed the agent a first-contact session that looked
     * identical to a pinned one.
     *
     * Walk what that costs: a hostile directory wins the race to your first contact with someone.
     * It mints a keypair and signs a consistent assignment, which internal mode accepts — correctly,
     * it cannot do otherwise — and THAT KEY BECOMES YOUR PERMANENT ANCHOR for that person. When the
     * real counterparty's genuinely-signed assignment arrives later, you refuse it and tell your
     * operator their contact may have been substituted, backwards. And the seal path reads the same
     * poisoned value as its trust anchor.
     *
     * None of that is preventable here — first contact has nothing to check against, and saying so
     * is the whole remedy. Which is why it must reach the agent.
     */
    const h = harness({ offeredDialer: REAL_DIALER, pinnedPrimary: null });
    await h.inject(REAL_DIALER, generateKeypair());
    await settle();

    const event = h.enqueued();
    expect(event, "the session must be accepted — first contact is legitimate").toBeDefined();
    expect(event?.verification, "the agent must be told this could not be checked against anything")
      .toBe("first_contact");
  });

  it("marks a REPEAT counterparty as pinned, so the two are distinguishable", async () => {
    // The negative control. Without it, the assertion above is satisfied by stamping
    // "first_contact" on every session, which would be a worse lie than saying nothing.
    const pinned = generateKeypair();
    const pinnedHex = Buffer.from(await pinned.getPublicKey()).toString("hex");

    const h = harness({ offeredDialer: REAL_DIALER, pinnedPrimary: pinnedHex });
    await h.inject(REAL_DIALER, pinned);
    await settle();

    expect(h.enqueued()?.verification).toBe("pinned");
  });

  it("ACCEPTS first contact, which is the stated bound of trust-on-first-use", async () => {
    // No pin ⇒ nothing independent to verify against, so the check falls back to internal
    // consistency. Worth nothing the first time, and saying so is the difference between a bound
    // and a gap.
    const h = harness({ offeredDialer: REAL_DIALER, pinnedPrimary: null });
    await h.inject(REAL_DIALER, generateKeypair());
    await settle();

    expect(h.events.find((e) => e.event === "session.inbound.counterparty_primary_changed")).toBeUndefined();
    expect(h.enqueued(), "the session must actually reach the agent").toBeDefined();
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

  it("does NOT accuse a PINNED counterparty of changing keys when the content was tampered", async () => {
    /**
     * 017-TBS review HIGH-2. A signature that fails under a pin has two possible causes, and only
     * one of them is about identity:
     *
     *   - the assignment NAMES a different signer than the pin  → `signer_not_pinned`, a real
     *     identity claim, and the case this agent should shout about;
     *   - the assignment names the RIGHT signer and the signature still fails → the CONTENT does
     *     not match what was signed. The counterparty's key has not changed at all.
     *
     * Collapsing the second into the first tells the operator their counterparty re-registered and
     * sends them to run `cello_contact_remove` — which DESTROYS a correct pin, the one security
     * anchor that was working, over what is usually a bug on the directory's side. That is not a
     * cosmetic mislabel: the remedy actively removes the protection.
     *
     * This is not hypothetical. 017 shipped a directory that signed twelve fields and encoded ten,
     * and every repeat counterparty would have been told exactly this.
     */
    const signer = generateKeypair();
    const signerHex = Buffer.from(await signer.getPublicKey()).toString("hex");
    const { frame } = await makeSignedAssignmentFrame({
      sessionId: SESSION_ID,
      initiatorPubkey: Buffer.from(COUNTERPARTY, "hex"),
      responderPubkey: Buffer.from(AGENT_PUBKEY, "hex"),
      initiatorSessionPeerId: REAL_DIALER,
      signWith: signer,
    });
    // The signer is EXACTLY the pinned key — identity is not in question. Only the content moved.
    (frame["assignment"] as Record<string, unknown>)["initiator_session_peer_id"] = "12D3KooWImpostor";

    const h = harness({ offeredDialer: "12D3KooWImpostor", pinnedPrimary: signerHex });
    h.injectRaw(frame);
    await settle();

    // Still refused — this is a real failure and must stay loud and blocking.
    const refused = h.events.find((e) => e.event === "session.inbound.assignment.invalid");
    expect(refused, "a content mismatch must still refuse the session").toBeDefined();

    // F6: name the reason. Without it, any EARLIER refusal that also emits assignment.invalid —
    // `inbound_assignment_unparseable`, say — would satisfy every assertion in this test.
    expect(String(refused?.context["reason"])).toBe("inbound_assignment_signature_invalid");

    // But NOT as an identity change, and the operator must not be told to clear their pin.
    const accused = h.events.find((e) => e.event === "session.inbound.counterparty_primary_changed");
    expect(accused, "the signer matched the pin — nothing about their identity changed").toBeUndefined();
    const guidance = String(refused?.context["guidance"] ?? "");
    expect(guidance).not.toMatch(/cello_contact_remove/);

    /**
     * F3: and it must not assert a cause it did not check. Under a pin the signature is verified
     * against a key recorded EARLIER, so a failure is equally well explained by the two sides
     * running different builds and disagreeing about what bytes get signed — which is exactly what
     * a half-finished version rollout looks like. Telling that operator the frame "was altered"
     * sends them to the network for something no retry can fix, and every directory node runs the
     * same build, so "try another node" is dead advice.
     */
    // Naming tampering as ONE of two causes is right; asserting it as the established one is not.
    // So this pins both halves rather than banning the word: the version cause must be named, and
    // the reader must be given the check that distinguishes them.
    expect(guidance, "the second cause must be named — a half-rolled upgrade produces this exact failure")
      .toMatch(/different CELLO versions/);
    expect(guidance, "name the check that separates the two causes; a retry cannot close a version gap")
      .toMatch(/cello -v/);
    // And specifically not the unpinned sentence, which asserts a conclusion this branch never reached.
    expect(guidance, "the unpinned wording asserts transit tampering as fact — wrong under a pin")
      .not.toMatch(/does not match its own contents/);
  });
});
