/**
 * DOD-M15-ASSIGN-TARGET-1 — THE PERMISSION SLIP MUST NAME WHO YOU ASKED FOR.
 *
 * `verifyAssignmentSignature` establishes that the assignment is FROST-signed by THIS AGENT'S OWN
 * threshold group key. It does not establish that the assignment is ABOUT the person the operator
 * named: `participant_b.pubkey` was never compared to `target_pubkey`, and `participant_a.pubkey`
 * was never compared to this agent's own key.
 *
 * ─── Why the return value alone is not the test ────────────────────────────────────────────────
 *
 * The substitution IS eventually caught downstream, and — review F3 — no plaintext was ever at
 * risk: content encryption binds to the operator's own `target_pubkey`, so an impostor cannot key
 * the session and a send with no key throws. What the dial costs instead is disclosure and
 * misattribution: we hand the impostor our session peer id and our IP, and the operator is then
 * told by `session.key.refused` that something *in the middle of the connection* substituted a key
 * — the relay and the network blamed for a fault that was entirely the directory's.
 *
 * So every refusal case here asserts that NOTHING DIALLED — `transportSelector.dial`,
 * `createSessionNode` and `connectToCounterparty` all uncalled. A test that only checked
 * `result.ok === false` would pass against an implementation that refuses AFTER dialling, which is
 * the entire defect this closes.
 *
 * The harness wires the REAL negotiator (`createOutboundSessions` with no injected negotiator) to
 * the REAL `cello_initiate_session` opener, so the negotiate → dial seam under test is production
 * wiring rather than a re-implementation of it.
 */

import { describe, it, expect } from "vitest";
import { generateKeypair } from "@cello-protocol/crypto";
import { createOutboundSessions, type OutboundSessionDeps } from "../outbound-sessions.js";
import { registerInitiateSessionHandler, type InitiateSessionDeps } from "../initiate-session-handler.js";
import { makeSignedAssignmentFrame, fixtureIdentity, FIXTURE_RESPONDER_PRIMARY } from "./helpers/signed-assignment.js";
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
const SESSION_ID = new Uint8Array(16).fill(7);
/** This agent's own K_local identity — what `participant_a` must carry. */
const OWN_PUBKEY = fixtureIdentity().pubkey;
/** The counterparty the operator actually typed — what `participant_b` must carry. */
const ASKED_FOR = fixtureIdentity().pubkey;
/** Somebody else entirely. */
const IMPOSTOR = fixtureIdentity().pubkey;

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** Everything the assignment names, and everything a dial would have touched. */
interface Harness {
  openSessionAs(agentName: string, params: Record<string, unknown>): Promise<Record<string, unknown>>;
  events: LogEvent[];
  /** Recorded so a refusal that happens too late is visible, not merely absent from the result. */
  dials: string[];
  sessionNodesCreated: string[];
  counterpartyConnects: string[][];
  /** 038-KEYBIND: the responder group keys the initiator pinned, in order. */
  counterpartyPrimaries: string[];
}

/**
 * Wire the real negotiator to the real opener over fakes.
 *
 * The directory is hostile in exactly the way the clause is about: it signs a perfectly valid
 * assignment with the agent's OWN quorum key (so the signature check passes) that names whoever
 * `participantA` / `participantB` say.
 */
async function makeHarness(opts: {
  participantA: Uint8Array;
  participantB: Uint8Array;
  /** 038-KEYBIND F5: a group key this daemon recorded for the counterparty in an earlier session. */
  pinnedCounterpartyPrimary?: string;
}): Promise<Harness> {
  const { logger, events } = makeLogger();
  const ourQuorum = generateKeypair();
  const ourQuorumHex = hex(await ourQuorum.getPublicKey());

  const { frame } = await makeSignedAssignmentFrame({
    sessionId: SESSION_ID,
    initiatorPubkey: opts.participantA,
    responderPubkey: opts.participantB,
    initiatorSessionPeerId: "12D3KooWInitiatorReceiver",
    signWith: ourQuorum,
  });

  let inbound: ((f: Record<string, unknown>) => void) | null = null;
  const HOME_NODE = "fake-dir";
  const signaling = {
    status: "connected",
    currentDirectoryNodeId: HOME_NODE,
    async sendRaw(f: unknown) {
      const type = (f as Record<string, unknown>)["type"];
      // Answer discovery so the request takes the production same-node route rather than the
      // legacy exhausted-fallback one (which costs 19s and exercises a path no initiator takes).
      if (type === "discovery_lookup") {
        inbound?.({ type: "discovery_lookup_result", state: "online", owning_node_ids: [HOME_NODE] });
      }
      if (type === "session_request") {
        inbound?.(frame);
      }
      return { ok: true as const };
    },
    registerInboundHandler(h: (f: Record<string, unknown>) => void) {
      inbound = h;
      return () => { inbound = null; };
    },
  };

  const dials: string[] = [];
  const sessionNodesCreated: string[] = [];
  const counterpartyConnects: string[][] = [];
  const counterpartyPrimaries: string[] = [];

  const sessionNodeManager = {
    getStandingReceiverInfo: () => ({ peerId: "12D3KooWInitiatorReceiver", addrs: ["/ip4/127.0.0.1/tcp/3"] }),
    getSessionNodePeerId: () => null,
    recordSessionGenesis: () => {},
    // 038-KEYBIND: the initiator records the responder's group key once the negotiation proved it.
    recordCounterpartyPrimary: (_agent: string, _sid: string, hex: string) => { counterpartyPrimaries.push(hex); },
    // 038-KEYBIND review F5: the pin the outbound path now compares against before dialling.
    getPinnedCounterpartyPrimary: () => opts.pinnedCounterpartyPrimary ?? null,
    createSessionNode: async (sessionId: string) => {
      sessionNodesCreated.push(sessionId);
      return { ok: true as const };
    },
    connectToCounterparty: async (_agent: string, _sid: string, addrs: string[]) => {
      counterpartyConnects.push(addrs);
      return { ok: true as const };
    },
    getSetting: () => null,
    hasDatabase: () => true,
    addContact: () => {},
  };

  const outbound = createOutboundSessions({
    logger,
    sessionNodeManager,
    getKeyProvider: () => generateKeypair(),
    getPersistence: () => ({
      async loadRegistrationState() {
        return {
          agentId: "agent-1",
          primaryPubkey: ourQuorumHex,
          mlDsaPubkey: "",
          registeredAt: 0,
          status: "registered",
        };
      },
      async listTrustSignalsForPresentation() { return []; },
      async loadOutboundMoniker() { return null; },
    }),
    getAgentSignaling: () => ({ signaling, getNode: () => null }),
    waitForSignalingConnected: async () => true,
    getFailoverEndpoint: async () => null,
    resolveConsortiumRoster: async () => null,
    registerSealListeners: () => () => {},
    getManifestVersion: () => 1,
    loadedAgents: [{ name: AGENT, pubkey: hex(OWN_PUBKEY) }],
  } as unknown as OutboundSessionDeps);

  const { openSessionAs } = registerInitiateSessionHandler({
    handlers: new Map(),
    logger,
    sessionNodeManager,
    getConnState: () => undefined,
    resolveCurrentAgent: () => AGENT,
    NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
    resolvedSessionNegotiator: outbound.resolvedSessionNegotiator,
    transportSelector: {
      async dial(assignment) {
        dials.push(hex(assignment.participant_b.pubkey));
        return { ok: true as const, mode: "relay" as const };
      },
    },
    autoNatService: { getDialability: () => ({ dialable: false, publicAddr: null }) },
    buildRelayConnectParams: async () => undefined,
  } as unknown as InitiateSessionDeps);

  return { openSessionAs, events, dials, sessionNodesCreated, counterpartyConnects, counterpartyPrimaries };
}

/** Every step that would have put bytes on the wire toward the named peer. */
function expectNothingDialled(h: Harness): void {
  expect(h.dials, "the transport selector must not have dialled anyone").toEqual([]);
  expect(h.sessionNodesCreated, "no session node may be stood up for a refused assignment").toEqual([]);
  expect(h.counterpartyConnects, "the counterparty's addresses must never have been contacted").toEqual([]);
}

describe("DOD-M15-ASSIGN-TARGET-1: the assignment must name who the operator asked for", () => {
  it("REFUSES — before anything dials — an assignment naming a different counterparty", async () => {
    // The colluding-quorum case: the slip verifies perfectly and is about somebody else.
    const h = await makeHarness({ participantA: OWN_PUBKEY, participantB: IMPOSTOR });

    const res = await h.openSessionAs(AGENT, { target_pubkey: hex(ASKED_FOR) });

    expect(res["ok"]).toBe(false);
    expect(res["reason"]).toBe("assignment_names_different_counterparty");
    expect(String(res["guidance"] ?? "")).not.toBe("");
    expectNothingDialled(h);

    // The refusal is on the durable record too, not only in the response.
    expect(h.events.find((e) => e.event === "session.assignment.target_mismatch")?.level).toBe("error");
    // And nothing reported the assignment as received-and-verified.
    expect(
      h.events.find((e) => e.event === "session.negotiate.assignment.received"),
      "an assignment about the wrong counterparty must not be logged as received",
    ).toBeUndefined();
  });

  it("REFUSES — before anything dials — an assignment putting a different agent in our own seat", async () => {
    const h = await makeHarness({ participantA: IMPOSTOR, participantB: ASKED_FOR });

    const res = await h.openSessionAs(AGENT, { target_pubkey: hex(ASKED_FOR) });

    expect(res["ok"]).toBe(false);
    expect(res["reason"]).toBe("assignment_names_different_self");
    expect(String(res["guidance"] ?? "")).not.toBe("");
    expectNothingDialled(h);

    expect(h.events.find((e) => e.event === "session.assignment.self_mismatch")?.level).toBe("error");
    expect(
      h.events.find((e) => e.event === "session.negotiate.assignment.received"),
      "an assignment naming someone else as this side must not be logged as received",
    ).toBeUndefined();
  });

  it("gives the two substitutions DISTINCT reasons — they are different events", async () => {
    const wrongTarget = await makeHarness({ participantA: OWN_PUBKEY, participantB: IMPOSTOR });
    const wrongSelf = await makeHarness({ participantA: IMPOSTOR, participantB: ASKED_FOR });

    const a = await wrongTarget.openSessionAs(AGENT, { target_pubkey: hex(ASKED_FOR) });
    const b = await wrongSelf.openSessionAs(AGENT, { target_pubkey: hex(ASKED_FOR) });

    expect(a["reason"]).not.toBe(b["reason"]);
    expect(a["guidance"]).not.toBe(b["guidance"]);
  });

  it("leaves a CORRECT assignment alone — the session is established and the dial happens", async () => {
    const h = await makeHarness({ participantA: OWN_PUBKEY, participantB: ASKED_FOR });

    const res = await h.openSessionAs(AGENT, { target_pubkey: hex(ASKED_FOR) });

    expect(res["ok"], `expected the correct assignment to establish, got ${JSON.stringify(res)}`).toBe(true);
    expect(h.dials).toEqual([hex(ASKED_FOR)]);
    /**
     * 038-KEYBIND review F3 — the value that gets PINNED, not "it did not refuse".
     *
     * `counterpartyPrimaries` was collected by the harness and asserted nowhere, so deleting
     * `recordCounterpartyPrimary` from `initiate-session-handler.ts` left every test in both repos
     * green while a responder-first seal went straight back to `signer_key_not_held` — the exact
     * regression DoD clause 7 exists to prevent.
     *
     * Asserted against the fixture's own exported constant, so a producer that starts emitting a
     * different key cannot pass by agreeing with a restated copy.
     */
    expect(
      h.counterpartyPrimaries,
      "the initiator must record the responder's group key — the seal anchor for a responder-first close",
    ).toEqual([hex(FIXTURE_RESPONDER_PRIMARY)]);
  });

  it("038-KEYBIND F5: REFUSES — before any dial — a counterparty group key that differs from the pin", async () => {
    /**
     * The mirror of the responder's `inbound_assignment_signer_not_pinned`. The binding already
     * stops a FORGED key; what it cannot stop on its own is a genuine but STALE binding for a group
     * key the counterparty no longer holds shares for, replayed by a directory that kept a copy.
     * Without this the initiator overwrote its own record with it, silently, and the damage surfaced
     * much later as a seal nobody could verify.
     */
    const h = await makeHarness({
      participantA: OWN_PUBKEY,
      participantB: ASKED_FOR,
      pinnedCounterpartyPrimary: "77".repeat(32),
    });

    const res = await h.openSessionAs(AGENT, { target_pubkey: hex(ASKED_FOR) });

    expect(res["ok"]).toBe(false);
    expect(res["reason"]).toBe("counterparty_primary_key_changed");
    // NOTHING dialled — a refusal after the dial has already handed the peer our session peer id
    // and, on a direct address, our IP.
    expectNothingDialled(h);
    // And the recorded key is NOT overwritten by the one that was refused.
    expect(h.counterpartyPrimaries).toEqual([]);
  });

  it("records NOTHING when the assignment is refused — a rejected key must never become the anchor", async () => {
    // The mirror of the assertion above, and the one that makes it mean something: a refusal path
    // that still pinned would write an impostor's key as the counterparty's permanent identity.
    const h = await makeHarness({ participantA: OWN_PUBKEY, participantB: IMPOSTOR });

    const res = await h.openSessionAs(AGENT, { target_pubkey: hex(ASKED_FOR) });

    expect(res["ok"]).toBe(false);
    expect(h.counterpartyPrimaries).toEqual([]);
  });

  it("compares CASE-INSENSITIVELY — an uppercase target_pubkey is the same counterparty", async () => {
    // `target_pubkey` is operator input and the negotiator accepts [0-9a-fA-F]{64}. A case-sensitive
    // compare would turn a correct session into a refusal.
    const h = await makeHarness({ participantA: OWN_PUBKEY, participantB: ASKED_FOR });

    const res = await h.openSessionAs(AGENT, { target_pubkey: hex(ASKED_FOR).toUpperCase() });

    expect(res["ok"], `an uppercase pubkey must not be refused, got ${JSON.stringify(res)}`).toBe(true);
    expect(h.dials).toEqual([hex(ASKED_FOR)]);
  });
});
