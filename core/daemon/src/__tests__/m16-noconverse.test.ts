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
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider, generateKeypair } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import type { CelloNode, ConnectResult, SignalingStream } from "@cello-protocol/transport";
import { startTwoConnectionFixture, FakeNode, FixedFactory, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { createInboundSessions, type InboundSessionDeps } from "../inbound-sessions.js";
import { wireSessionOfferHandler } from "../session-ceremony.js";
import { startDaemon } from "../daemon.js";
import { DbRegistrationPersistence } from "../db-identity-store.js";
import { REFUSAL_GUIDANCE, REFUSAL_REASONS } from "../refusal-reasons.js";
import { TIER } from "../contacts-tier-migration.js";
import { makeSignedAssignmentFrame, fixtureIdentity, registerFixtureSigner } from "./helpers/signed-assignment.js";
import type { SessionNegotiator } from "../transport-selector.js";
import type { DaemonConfig, Logger } from "../types.js";

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

function inboundHarness(opts: { tier?: number } = {}) {
  const events: Array<{ event: string; context: Record<string, unknown> }> = [];
  const push = () => (event: string, context?: Record<string, unknown>) => {
    events.push({ event, context: context ?? {} });
  };
  const logger: Logger = { debug: push(), info: push(), warn: push(), error: push() };
  /**
   * ⚠️ EVERY HANDLER, NOT THE LAST ONE. The production wiring registers several handlers on one
   * stream (seal-interrupted, session_assignment, session_refused), and a stub holding a single
   * slot silently keeps whichever registered LAST — so injecting an assignment reached nothing the
   * moment a third handler was added, and every test here failed for a reason that had nothing to
   * do with what it was testing. The real manager fans out; so does this.
   */
  const inboundHandlers: Array<(frame: Record<string, unknown>) => void> = [];
  const inbound = (frame: Record<string, unknown>): void => { for (const h of [...inboundHandlers]) h(frame); };

  const durable: Array<{ agent: string; session: string; reason: string }> = [];
  /** Re-closing the receiver gate to the offered dialer — half of what `refuseInboundSession` does. */
  const revoked: Array<{ agent: string; session: string; dialer: string | null }> = [];
  /** Frames sent back to the counterparty — the `session_refused` notice a KNOWN+ caller earns. */
  const sentFrames: Array<Record<string, unknown>> = [];
  /** M16 019: whether alice subscribes to the dialling counterparty. Off unless a test says so. */
  let aliceSubscribes = false;

  const sessionNodeManager = {
    getOfferedDialer: () => DIALER,
    clearOfferedDialer: () => {},
    revokeOfferedDialer: async (agent: string, session: string, dialer: string | null) => {
      revoked.push({ agent, session, dialer });
    },
    recordRefusedSession: (agent: string, session: string, reason: string) => {
      durable.push({ agent, session, reason });
    },
    getTier: () => opts.tier ?? TIER.UNKNOWN,
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
    /**
     * M16 019: alice SUBSCRIBES to the counterparty, which is therefore a channel as far as she is
     * concerned. Nothing else in this harness changes — the point is that the same verified
     * assignment she would otherwise accept is refused because of who it is FROM.
     */
    isSubscribedChannel: (name: string, counterpartyHex: string) =>
      name === ALICE && counterpartyHex.toLowerCase() === COUNTERPARTY.toLowerCase() && aliceSubscribes,
    sharedSignaling: {
      registerInboundHandler(h: (frame: Record<string, unknown>) => void) {
        inboundHandlers.push(h);
        return () => { const i = inboundHandlers.indexOf(h); if (i >= 0) inboundHandlers.splice(i, 1); };
      },
    },
    sendOver: async (_agent: string, frame: Record<string, unknown>) => {
      sentFrames.push(frame);
      return { ok: true };
    },
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

  async function inject(
    toPubkeyHex: string,
    sessionId: Uint8Array,
    injectOpts: { breakSignature?: boolean; noCounterpartyEndpoint?: boolean } = {},
  ) {
    const { frame } = await makeSignedAssignmentFrame({
      sessionId,
      initiatorPubkey: Buffer.from(COUNTERPARTY, "hex"),
      responderPubkey: Buffer.from(toPubkeyHex, "hex"),
      initiatorSessionPeerId: DIALER,
      ...(injectOpts.noCounterpartyEndpoint ? { counterpartySessionPeerId: "" } : {}),
      signWith: generateKeypair(),
    });
    if (injectOpts.breakSignature) {
      const assignment = frame["assignment"] as { directory_signature: Uint8Array };
      const sig = Uint8Array.from(assignment.directory_signature);
      sig[0] ^= 0x01;
      assignment.directory_signature = sig;
    }
    inbound(frame);
  }

  return {
    inject,
    events,
    durable,
    revoked,
    sentFrames,
    operatorSees: (agent: string) => (api.refusedSessionRequests.get(agent) ?? []) as Array<{ reason: string }>,
    enqueued: (agent: string) => api.inboundSessionQueues.get(agent) ?? [],
    /** M16 019: make alice a subscriber of the dialling counterparty. */
    subscribeAliceToCaller: () => { aliceSubscribes = true; },
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
    // Through the refusal machinery, not a bare record: the gate is re-closed to the offered dialer.
    expect(h.revoked).toEqual([{ agent: CHAN, session: "01".repeat(16), dialer: DIALER }]);
  });

  it("a KNOWN caller refused by a channel is told to reach the admin", async () => {
    const h = inboundHarness({ tier: TIER.KNOWN });
    await h.inject(CHAN_PUBKEY, new Uint8Array(16).fill(4));
    await settle();
    const notice = h.sentFrames.find((f) => f["type"] === "session_refused");
    expect(notice, "a KNOWN caller must be told why").toBeDefined();
    expect(notice!["reason"]).toBe(REFUSAL_REASONS.SESSION_TO_CHANNEL_IDENTITY);
    expect(String(notice!["guidance"])).toMatch(/admin/);
  });

  it("an assignment with no counterparty endpoint re-closes the gate to the offered dialer", async () => {
    // Review LOW [pre-existing]: this refusal was a bare return, leaving the receiver open to the
    // dialer the offer named until the next offer reused it.
    const h = inboundHarness();
    await h.inject(ALICE_PUBKEY, new Uint8Array(16).fill(5), { noCounterpartyEndpoint: true });
    await settle();
    expect(h.enqueued(ALICE)).toHaveLength(0);
    expect(h.revoked).toEqual([{ agent: ALICE, session: "05".repeat(16), dialer: DIALER }]);
  });

  it("the same assignment to a NON-channel agent is accepted", async () => {
    const h = inboundHarness();
    await h.inject(ALICE_PUBKEY, new Uint8Array(16).fill(2));
    await settle();
    expect(h.durable).toEqual([]);
    expect(h.enqueued(ALICE), "the session must actually reach the agent's queue").toHaveLength(1);
  });

  it("21. a session FROM a channel this agent SUBSCRIBES to is refused with its own reason", async () => {
    const h = inboundHarness();
    h.subscribeAliceToCaller();

    // The identical assignment that the test above proves alice ACCEPTS.
    await h.inject(ALICE_PUBKEY, new Uint8Array(16).fill(9));
    await settle();

    /**
     * ⚠️ **THE MIRROR OF THE CHECK ABOVE, AND IT CATCHES WHAT THAT ONE CANNOT.** That one holds when
     * somebody dials OUR channel. This one is a channel dialling US — either its key is in somebody
     * else's hands, or someone has learned a channel's pubkey and is trading on the trust the
     * operator already places in it. A subscriber is the least equipped person to doubt that
     * identity, because they already read and believe it.
     */
    expect(h.durable.map((d) => d.reason)).toEqual([REFUSAL_REASONS.SESSION_FROM_SUBSCRIBED_CHANNEL]);
    expect(h.enqueued(ALICE), "nothing reaches the agent").toHaveLength(0);
    // Durable and revoked, like every other refusal on this path — not a silent drop.
    expect(h.revoked).toHaveLength(1);
    expect(h.operatorSees(ALICE).map((r) => r.reason))
      .toContain(REFUSAL_REASONS.SESSION_FROM_SUBSCRIBED_CHANNEL);
  });

  it("21b. its guidance tells the operator to be SUSPICIOUS, not that something is broken", () => {
    const guidance = REFUSAL_GUIDANCE[REFUSAL_REASONS.SESSION_FROM_SUBSCRIBED_CHANNEL];
    expect(typeof guidance).toBe("string");
    // The sibling refusal says "there is nothing wrong and nothing to retry" — correct there, and
    // exactly wrong here. This one is a signal about the counterparty, and must read as one.
    expect(guidance.toLowerCase()).toContain("suspicious");
    // It must point somewhere the operator can actually go, and that is the channel's ADMIN agent.
    expect(guidance.toLowerCase()).toContain("admin");
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

// ─── Offer: a channel rejects before revealing where it can be dialled ────────────────────────

describe("M16 006-NOCONVERSE: a channel rejects a session offer", () => {
  function wireOffer(isChannel: boolean) {
    const sent: Array<Record<string, unknown>> = [];
    let handler: ((frame: Record<string, unknown>) => void) | null = null;
    const reservations: string[] = [];
    const admitted: string[] = [];
    const events: Array<{ event: string; context: Record<string, unknown> }> = [];
    const push = () => (event: string, context?: Record<string, unknown>) => { events.push({ event, context: context ?? {} }); };
    wireSessionOfferHandler({
      agentName: "chan",
      getStandingReceiverEndpoint: () => ({ peerId: "12D3KooWChanReceiver", addrs: ["/ip4/127.0.0.1/tcp/9"] }),
      reserveOnDemand: async (circuitAddr) => { reservations.push(circuitAddr); return true; },
      admitOfferedDialer: (peerId) => { admitted.push(peerId); return "narrowed" as const; },
      isChannelAgent: () => isChannel,
      signaling: {
        status: "connected",
        async sendRaw(frame: unknown) { sent.push(frame as Record<string, unknown>); return { ok: true as const }; },
        registerInboundHandler(h: (frame: Record<string, unknown>) => void) { handler = h; return () => { handler = null; }; },
      } as unknown as Parameters<typeof wireSessionOfferHandler>[0]["signaling"],
      logger: { debug: push(), info: push(), warn: push(), error: push() },
    });
    const offer = {
      type: "session_offer",
      session_id: new Uint8Array(16).fill(6),
      initiator_session_peer_id: "12D3KooWInitiator",
      relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: ["/ip4/127.0.0.1/tcp/5/p2p/12D3KooWRelay"] },
    };
    return { sent, reservations, admitted, events, fire: () => handler?.(offer) };
  }

  it("a channel answers an offer with a reject, and takes no relay slot and advertises no endpoint", async () => {
    // Review MEDIUM: accepting first sent the channel's session peer id and addresses to the caller
    // and spent a relay reservation, all before the assignment refusal. "Is THIS local agent a
    // channel?" needs no authenticated frame, so it can be answered here.
    const w = wireOffer(true);
    w.fire();
    await settle();
    const reject = w.sent.find((f) => f["type"] === "session_offer_reject");
    expect(reject?.["reason"]).toBe("channel_identity");
    expect(w.sent.find((f) => f["type"] === "session_offer_accept")).toBeUndefined();
    expect(w.reservations).toEqual([]);
    expect(w.admitted).toEqual([]);
  });

  it("a non-channel still accepts the same offer", async () => {
    const w = wireOffer(false);
    w.fire();
    await settle();
    expect(w.sent.find((f) => f["type"] === "session_offer_accept")).toBeDefined();
    expect(w.reservations).toHaveLength(1);
  });
});

// ─── The running daemon wires the inbound refusal ─────────────────────────────────────────────

describe("M16 006-NOCONVERSE: a real daemon refuses an inbound session to its channel", () => {
  let tempDir: string | undefined;
  let handle: Awaited<ReturnType<typeof startDaemon>> | undefined;

  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* already stopped */ } }
    handle = undefined;
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
    tempDir = undefined;
  });

  it("the stored channel flag, not a test stub, refuses the assignment; a plain neighbour accepts", async () => {
    // Review HIGH: every other inbound test hands createInboundSessions its own isChannelAgent. This
    // one goes through startDaemon, the stored flag and the real refused_sessions table, so breaking
    // the daemon's wiring turns it red.
    tempDir = await mkdtemp(join(tmpdir(), "cello-m16-006-inbound-"));
    const pubkeys = new Map<string, string>();
    for (const name of ["chan", "bob"]) {
      const dir = join(tempDir, "agents", name);
      await mkdir(dir, { recursive: true });
      const kp = await FileKeyProvider.load(join(dir, "key"));
      const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
      registerFixtureSigner(hex, kp);
      pubkeys.set(name, hex);
    }
    let inbound: ((frame: unknown) => void) | null = null;
    const stream: SignalingStream = {
      send: async () => {},
      onMessage: (h: (frame: unknown) => void) => { inbound = h; },
      close: () => {},
    };
    const config: DaemonConfig = {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      sessionNodeFactory: new FixedFactory(new FakeNode() as unknown as CelloNode),
      signalingConnect: async (): Promise<ConnectResult> => ({ stream, directoryNodeId: "fake-dir", manifestVersion: 1 }),
    };
    handle = await startDaemon(config);
    await new Promise((r) => setTimeout(r, 50));
    const snm = handle.getSessionNodeManager();
    await new DbRegistrationPersistence({ db: snm.getDb(), agentName: "chan", logger: config.logger }).persistRegistrationState({
      agentId: "fixture-channel-chan", primaryPubkey: "5b".repeat(32), mlDsaPubkey: "6c".repeat(32),
      registeredAt: Date.now(), keyBinding: "7d".repeat(64), channel: true, adminPubkey: pubkeys.get("bob")!,
    });
    await snm.ensureStandingReceiverForAgent("chan");
    await snm.ensureStandingReceiverForAgent("bob");

    const push = async (to: string, fill: number) => {
      const { frame } = await makeSignedAssignmentFrame({
        sessionId: new Uint8Array(16).fill(fill),
        initiatorPubkey: Buffer.from(COUNTERPARTY, "hex"),
        responderPubkey: Buffer.from(pubkeys.get(to)!, "hex"),
        initiatorSessionPeerId: "12D3KooWInitiator",
        counterpartySessionPeerId: "12D3KooWReceiver",
      });
      inbound(frame);
    };
    await push("chan", 7);
    await push("bob", 8);
    await new Promise((r) => setTimeout(r, 150));

    expect(snm.wasSessionRefused("chan", "07".repeat(16)), "the refusal must land in the real store").toBe(true);
    expect(snm.getSessionRecord("chan", "07".repeat(16))).toBeFalsy();
    expect(snm.wasSessionRefused("bob", "08".repeat(16))).toBe(false);
    expect(snm.getSessionRecord("bob", "08".repeat(16))?.status).toBe("active");
  });
});
