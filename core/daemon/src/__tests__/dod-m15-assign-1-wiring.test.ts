/**
 * DOD-M15-ASSIGN-1 clause (a), THE WIRING — "the daemon verifies", not "a function verifies".
 *
 * The review found this gap and it is the one that mattered most: `verifyAssignmentSignature` had
 * four unit tests, and the call site that invokes it had none. Deleting the call from
 * `outbound-sessions.ts` and returning `{ ok: true, assignment }` left the entire 4018-test gate
 * green. What was proven was that a function verifies; the DoD line says the DAEMON verifies.
 *
 * Nothing else in the tree covers it, and not by oversight: every existing two-daemon harness
 * injects its own `sessionNegotiator`, which replaces the code path the verification lives on. So
 * this file builds the REAL negotiator — `createOutboundSessions` with no injected negotiator — and
 * feeds it what a hostile directory would send.
 */

import { describe, it, expect } from "vitest";
import { generateKeypair, CONTEXT_SESSION_ESTABLISHMENT } from "@cello-protocol/crypto";
import { buildSessionEstablishmentTbs, computeGenesisPrevRoot } from "@cello-protocol/protocol-types";
import { createOutboundSessions, type OutboundSessionDeps } from "../outbound-sessions.js";
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

const SESSION_ID = new Uint8Array(16).fill(7);
const TS = 1_700_000_000_000;
const AGENT = "alice";

/**
 * Build the `session_assignment` frame a directory would push back, FROST-signed by `signWith` and
 * announcing `signWith`'s key as the signer.
 *
 * A hostile directory can do exactly this: the signature is real and internally consistent. What it
 * cannot do is make the signing key be the agent's own threshold group key — which is the anchor
 * the verifier checks, and the reason this test is about the wiring rather than the crypto.
 */
async function assignmentFrame(opts: {
  signWith: ReturnType<typeof generateKeypair>;
  pubA: Uint8Array;
  pubB: Uint8Array;
  counterpartyPeerId: string;
}): Promise<Record<string, unknown>> {
  const initiatorPeerId = "12D3KooWInitiatorReceiver";
  const initiatorAddrs = ["/ip4/127.0.0.1/tcp/3"];
  const counterpartyAddrs = ["/ip4/127.0.0.1/tcp/4"];
  const genesis = computeGenesisPrevRoot(opts.pubA, opts.pubB, SESSION_ID, TS);
  const tbs = buildSessionEstablishmentTbs(
    SESSION_ID, opts.pubA, opts.pubB, genesis, TS,
    initiatorPeerId, initiatorAddrs, opts.counterpartyPeerId, counterpartyAddrs, "relay",
  );
  const enc = new TextEncoder().encode(CONTEXT_SESSION_ESTABLISHMENT);
  const framed = new Uint8Array(enc.length + 1 + tbs.length);
  framed.set(enc, 0); framed[enc.length] = 0x00; framed.set(tbs, enc.length + 1);
  const sig = await opts.signWith.sign(framed);

  return {
    type: "session_assignment",
    assignment: {
      session_id: SESSION_ID,
      participant_a: { pubkey: opts.pubA, peer_id: "12D3KooWA", multiaddrs: [] },
      participant_b: { pubkey: opts.pubB, peer_id: "12D3KooWB", multiaddrs: [] },
      relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: ["/ip4/127.0.0.1/tcp/1"] },
      directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: ["/ip4/127.0.0.1/tcp/2"] },
      session_timestamp: TS,
      directory_pubkey: new Uint8Array(32).fill(0xdd),
      directory_signature: sig,
      signature_type: "frost",
      signer_pubkey: await opts.signWith.getPublicKey(),
      initiator_session_peer_id: initiatorPeerId,
      initiator_session_addrs: initiatorAddrs,
      counterparty_session_peer_id: opts.counterpartyPeerId,
      counterparty_session_addrs: counterpartyAddrs,
      transport_mode: "relay",
    },
  };
}

/** Wire the REAL negotiator — no `sessionNegotiator` override — over fakes. */
function makeNegotiator(opts: {
  logger: Logger;
  ourPrimaryPubkeyHex: string;
  agentKeyProvider: ReturnType<typeof generateKeypair>;
  onRequest: (send: (frame: Record<string, unknown>) => void) => void;
}) {
  let inbound: ((frame: Record<string, unknown>) => void) | null = null;

  /**
   * Review N2 — ANSWER THE DISCOVERY LOOKUP, so this test runs the production route.
   *
   * The first version's fake answered only `session_request`. The negotiator therefore ran its
   * discovery loop to exhaustion (three 5s lookups plus backoffs — 19 seconds), gave up, and
   * reached the code under test through the LEGACY unsupported-directory fallback. The assertion
   * was real and the revert test genuine, but it paid 19s of gate time per run and exercised a path
   * no live agent takes. Worse, if that exhausted branch is ever made consistent with its siblings
   * (which return `directory_unreachable` rather than falling through), this test would go red for
   * an unrelated reason and the tempting repair would be to weaken the assertion.
   *
   * Answering `discovery_lookup` with "online, homed on the node we are already talking to" puts it
   * on the `same_node` path — what an initiator actually does — and it finishes in milliseconds.
   */
  const HOME_NODE = "fake-dir";
  const signaling = {
    status: "connected",
    currentDirectoryNodeId: HOME_NODE,
    async sendRaw(frame: unknown) {
      const type = (frame as Record<string, unknown>)["type"];
      if (type === "discovery_lookup") {
        inbound?.({ type: "discovery_lookup_result", state: "online", owning_node_ids: [HOME_NODE] });
      }
      if (type === "session_request") {
        // The directory answers asynchronously, as it does in production.
        opts.onRequest((f) => inbound?.(f));
      }
      return { ok: true as const };
    },
    registerInboundHandler(h: (frame: Record<string, unknown>) => void) {
      inbound = h;
      return () => { inbound = null; };
    },
  };

  const deps = {
    logger: opts.logger,
    sessionNodeManager: {
      getStandingReceiverInfo: () => ({ peerId: "12D3KooWInitiatorReceiver", addrs: ["/ip4/127.0.0.1/tcp/3"] }),
      getSessionNodePeerId: () => null,
    },
    getKeyProvider: () => opts.agentKeyProvider,
    getPersistence: () => ({
      async loadRegistrationState() {
        return {
          agentId: "agent-1",
          primaryPubkey: opts.ourPrimaryPubkeyHex,
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
    loadedAgents: [{ name: AGENT, pubkey: "aa".repeat(32) }],
  } as unknown as OutboundSessionDeps;

  return createOutboundSessions(deps).resolvedSessionNegotiator;
}

describe("DOD-M15-ASSIGN-1 (a) wiring: the DAEMON refuses an assignment it cannot verify", () => {
  it("REFUSES a session when the directory signs the assignment with a key that is not this agent's own", async () => {
    // The attack the clause exists to stop: whichever directory node this daemon is talking to
    // hands it a permission slip naming an impostor's peer id. The slip is properly signed — just
    // not by this agent's threshold quorum, which no single node can speak for.
    const hostileDirectory = generateKeypair();
    const ourQuorum = generateKeypair();
    const { logger, events } = makeLogger();

    const pubA = new Uint8Array(32).fill(0xaa);
    const pubB = new Uint8Array(32).fill(0xbb);

    const negotiator = makeNegotiator({
      logger,
      ourPrimaryPubkeyHex: Buffer.from(await ourQuorum.getPublicKey()).toString("hex"),
      agentKeyProvider: generateKeypair(),
      onRequest: (send) => {
        void assignmentFrame({
          signWith: hostileDirectory,
          pubA, pubB,
          counterpartyPeerId: "12D3KooWImpostor",
        }).then((frame) => send(frame));
      },
    });

    const result = await negotiator.negotiate({
      agentName: AGENT,
      correlationId: "corr-1",
      advertisedAddress: { peerId: "12D3KooWInitiatorReceiver", addrs: ["/ip4/127.0.0.1/tcp/3"] },
      params: { target_pubkey: Buffer.from(pubB).toString("hex") },
    } as never);

    // PIN THE ROUTE (review N2). Without this, a future change that breaks discovery sends the test
    // quietly back through the legacy exhausted-fallback path — still passing, still 19 seconds,
    // and no longer testing what an initiator actually does.
    expect(
      events.find((e) => e.event === "session.discovery.unsupported_fallback"),
      "this must reach the verifier by the production same-node route, not the legacy fallback",
    ).toBeUndefined();

    expect(result.ok, "the daemon must refuse an assignment signed by a key that is not its own quorum").toBe(false);
    expect(result.ok === false && result.reason).toBe("assignment_signer_not_this_agent");
    // The refusal is recorded where an operator would look, not only returned to the caller.
    expect(events.find((e) => e.event === "session.assignment.signer_mismatch")?.level).toBe("error");
    // And NOTHING reported the assignment as received-and-verified.
    expect(
      events.find((e) => e.event === "session.negotiate.assignment.received"),
      "an assignment that failed verification must not be logged as received",
    ).toBeUndefined();
  });
});
