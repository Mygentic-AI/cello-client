/**
 * M16 006-NOCONVERSE — a broadcast channel never converses, enforced by the daemon that holds it.
 *
 * Two doors:
 *   1. OUTBOUND — a session is never initiated AS a channel. Driven through a real daemon and its
 *      IPC socket (`two-connection-fixture`), with a recording negotiator so the test can see that a
 *      refused initiate never asked the directory for anything.
 *   2. INBOUND — a VERIFIED assignment addressed TO one of this daemon's channels is refused through
 *      `refuseInboundSession`. Driven through the real `createInboundSessions` over fake deps with a
 *      genuinely signed assignment — the pattern `dod-m15-offer-signed-1.test.ts` established,
 *      because the real-daemon fixture has no directory stream to push an assignment down.
 */

import { describe, it, expect, afterEach } from "vitest";
import { generateKeypair } from "@cello-protocol/crypto";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { createInboundSessions, type InboundSessionDeps } from "../inbound-sessions.js";
import { REFUSAL_GUIDANCE, REFUSAL_REASONS } from "../refusal-reasons.js";
import { TIER } from "../contacts-tier-migration.js";
import { makeSignedAssignmentFrame, fixtureIdentity } from "./helpers/signed-assignment.js";
import type { SessionNegotiator } from "../transport-selector.js";
import type { Logger } from "../types.js";

// ─── Outbound ──────────────────────────────────────────────────────────────────────────────────

describe("M16 006-NOCONVERSE: a channel cannot initiate a session", () => {
  let fx: TwoConnectionFixture | undefined;
  afterEach(async () => {
    await fx?.cleanup();
    fx = undefined;
  });

  /** Records every negotiate call and refuses it, so nothing past the negotiator runs. */
  function recordingNegotiator(): { negotiator: SessionNegotiator; calls: string[] } {
    const calls: string[] = [];
    const negotiator = {
      async negotiate(ctx: { agentName: string }) {
        calls.push(ctx.agentName);
        return { ok: false as const, reason: "negotiator_reached_by_test", guidance: "test stop" };
      },
    } as unknown as SessionNegotiator;
    return { negotiator, calls };
  }

  it("initiating as a channel is refused at the IPC entry", async () => {
    const { negotiator, calls } = recordingNegotiator();
    fx = await startTwoConnectionFixture({ agents: ["chan", "alice"], channelAgents: ["chan"], sessionNegotiator: negotiator });
    const client = await fx.connectAs("chan");
    const result = (await client.send("cello_initiate_session", { target_pubkey: "ab".repeat(32) })) as {
      ok: boolean; reason?: string; guidance?: string;
    };
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("channel_cannot_initiate");
    expect(result.guidance).toMatch(/broadcast channel/);
    const refused = fx.eventsNamed("session.initiate.refused_channel");
    expect(refused).toHaveLength(1);
    expect(refused[0]!.ctx["agent_name"]).toBe("chan");
    expect(typeof refused[0]!.ctx["correlationId"]).toBe("string");
    expect(calls, "a refused initiate must not ask the directory for anything").toEqual([]);
  });

  it("initiating as a plain agent still works past the gate", async () => {
    const { negotiator, calls } = recordingNegotiator();
    fx = await startTwoConnectionFixture({ agents: ["chan", "alice"], channelAgents: ["chan"], sessionNegotiator: negotiator });
    const client = await fx.connectAs("alice");
    const result = (await client.send("cello_initiate_session", { target_pubkey: "ab".repeat(32) })) as {
      ok: boolean; reason?: string;
    };
    expect(result.reason).toBe("negotiator_reached_by_test");
    expect(calls).toEqual(["alice"]);
    expect(fx.eventsNamed("session.initiate.refused_channel")).toHaveLength(0);
  });
});

// ─── Inbound ───────────────────────────────────────────────────────────────────────────────────

const CHAN = "chan";
const CHAN_PUBKEY = "c1".repeat(32);
const ALICE = "alice";
const ALICE_PUBKEY = "a1".repeat(32);
const COUNTERPARTY = fixtureIdentity().pubkeyHex;
const DIALER = "12D3KooWInitiator";

function inboundHarness() {
  const events: Array<{ event: string; context: Record<string, unknown> }> = [];
  const push = () => (event: string, context?: Record<string, unknown>) => {
    events.push({ event, context: context ?? {} });
  };
  const logger: Logger = { debug: push(), info: push(), warn: push(), error: push() };
  let inbound: ((frame: Record<string, unknown>) => void) | null = null;
  const durable: Array<{ agent: string; session: string; reason: string }> = [];

  const sessionNodeManager = {
    getOfferedDialer: () => DIALER,
    clearOfferedDialer: () => {},
    revokeOfferedDialer: async () => {},
    recordRefusedSession: (agent: string, session: string, reason: string) => {
      durable.push({ agent, session, reason });
    },
    getTier: () => TIER.UNKNOWN,
    resolveTierBound: () => 3,
    getPinnedCounterpartyPrimary: () => null,
    getSessionRecord: () => undefined,
    ensureStandingReceiverForAgent: async () => {},
    getStandingReceiverReady: () => true,
    checkUnknownSenderAcceptanceBound: () => ({ ok: true as const }),
    sessionsConsumingCap: () => 0,
    capDiagnostics: () => ({}),
    recordCounterpartyPrimary: () => {},
    recordOfferedMoniker: () => {},
    addContact: () => {},
    recordSessionGenesis: () => {},
    acceptSession: async () => ({ ok: true }),
    resolveAgentId: () => "agent-id",
    getDb: () => { throw new Error("no db in this harness"); },
  };

  const deps = {
    logger,
    sessionNodeManager,
    agents: [{ name: CHAN, pubkey: CHAN_PUBKEY }, { name: ALICE, pubkey: ALICE_PUBKEY }],
    isChannelAgent: (name: string) => name === CHAN,
    sharedSignaling: {
      registerInboundHandler(h: (frame: Record<string, unknown>) => void) {
        inbound = h;
        return () => {};
      },
    },
    sendOver: async () => ({ ok: true }),
    isExplicitlyOffline: () => false,
    getConnState: () => undefined,
    resolveCurrentAgent: () => null,
    NO_CURRENT_AGENT_RESPONSE: {},
    getKeyProvider: () => undefined,
    handleInboundSealInterruptedRequest: async () => {},
    reapDeadHalfOpenSessions: () => {},
    sendAwayResponse: async () => {},
    dispatchSessionStateChangedWithTelegram: () => {},
    sendTelegramDoorbell: async () => {},
    isDeliveryOpenToAgent: () => false,
  } as unknown as InboundSessionDeps;

  const api = createInboundSessions(deps);

  async function inject(toPubkeyHex: string, sessionId: Uint8Array, opts: { breakSignature?: boolean } = {}) {
    const { frame } = await makeSignedAssignmentFrame({
      sessionId,
      initiatorPubkey: Buffer.from(COUNTERPARTY, "hex"),
      responderPubkey: Buffer.from(toPubkeyHex, "hex"),
      initiatorSessionPeerId: DIALER,
      signWith: generateKeypair(),
    });
    if (opts.breakSignature) {
      const assignment = frame["assignment"] as { directory_signature: Uint8Array };
      const sig = Uint8Array.from(assignment.directory_signature);
      sig[0] ^= 0x01;
      assignment.directory_signature = sig;
    }
    inbound?.(frame);
  }

  return {
    inject,
    events,
    durable,
    operatorSees: (agent: string) => (api.refusedSessionRequests.get(agent) ?? []) as Array<{ reason: string }>,
    enqueued: (agent: string) => api.inboundSessionQueues.get(agent) ?? [],
  };
}

async function settle(): Promise<void> {
  for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
}

describe("M16 006-NOCONVERSE: a channel refuses an inbound session", () => {
  it("a verified inbound assignment TO a channel is refused with the named reason", async () => {
    const h = inboundHarness();
    await h.inject(CHAN_PUBKEY, new Uint8Array(16).fill(1));
    await settle();
    expect(h.durable).toEqual([
      { agent: CHAN, session: "01".repeat(16), reason: REFUSAL_REASONS.SESSION_TO_CHANNEL_IDENTITY },
    ]);
    expect(h.operatorSees(CHAN).map((r) => r.reason)).toEqual([REFUSAL_REASONS.SESSION_TO_CHANNEL_IDENTITY]);
    expect(h.enqueued(CHAN)).toHaveLength(0);
  });

  it("the same assignment to a NON-channel agent is accepted", async () => {
    const h = inboundHarness();
    await h.inject(ALICE_PUBKEY, new Uint8Array(16).fill(2));
    await settle();
    expect(h.durable).toEqual([]);
    expect(h.enqueued(ALICE), "the session must actually reach the agent's queue").toHaveLength(1);
  });

  it("the refusal fires AFTER signature verification", async () => {
    const h = inboundHarness();
    await h.inject(CHAN_PUBKEY, new Uint8Array(16).fill(3), { breakSignature: true });
    await settle();
    expect(h.durable.map((d) => d.reason)).toEqual([REFUSAL_REASONS.INBOUND_ASSIGNMENT_INVALID]);
    expect(h.durable.map((d) => d.reason)).not.toContain(REFUSAL_REASONS.SESSION_TO_CHANNEL_IDENTITY);
  });

  it("guidance is total", () => {
    const guidance = REFUSAL_GUIDANCE[REFUSAL_REASONS.SESSION_TO_CHANNEL_IDENTITY];
    expect(typeof guidance).toBe("string");
    expect(guidance.length).toBeGreaterThan(0);
    expect(guidance).toMatch(/admin/);
  });
});
