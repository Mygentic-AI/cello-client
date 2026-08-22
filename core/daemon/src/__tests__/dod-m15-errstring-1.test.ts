/**
 * DOD-M15-ERRSTRING-1 — an error names what was OBSERVED, never an inferred conclusion.
 *
 * One string, `counterparty_offline`, was returned on 2026-08-16 for a garbage-collecting node, a
 * roster below threshold, and a stale gateway. The counterparty was online in all three, and none of
 * the three faults was theirs. Most of a day went into the wrong subsystem, because the error named
 * a party rather than an observation.
 *
 * Two of its four producers were asserting something nothing had checked:
 *
 *   1. **The no-home branch** returned `counterparty_offline` while its own guidance said, in the
 *      next sentence, *"the directory reported the counterparty online"*. The two halves of one
 *      message contradicted each other, and the half an operator acts on was the wrong one.
 *   2. **The exhausted-loop fallthrough** returned it as a catch-all. Traced rather than assumed,
 *      that line turns out to be UNREACHABLE — every branch returns — so it is a compiler backstop,
 *      not the source of the incident. It still must not name a party: a backstop that fires is by
 *      definition an unpredicted case, which is the worst moment to blame someone specific. Changed
 *      for that reason, and not tested here, because a test that cannot reach its subject proves
 *      nothing.
 *
 * The other two producers are correct and are pinned here so this unit cannot over-correct them: a
 * directory that says "offline" is quoted, not second-guessed.
 */

import { describe, it, expect } from "vitest";
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

const HOME = "home-node";
const AGENT = "alice";
const TARGET = "bb".repeat(32);

/**
 * Drive the REAL negotiator (no injected `sessionNegotiator`) with a directory that answers the
 * discovery lookup however the test needs, and never answers `session_request`.
 *
 * `answerDiscovery` returns the frame to push back, or null to stay silent.
 */
function negotiatorWith(
  answerDiscovery: () => Record<string, unknown> | null,
  unresolved: ReadonlyArray<{ nodeId: string; reason: string }> = [],
) {
  const { logger, events } = makeLogger();
  let inbound: ((frame: Record<string, unknown>) => void) | null = null;

  const signaling = {
    status: "connected",
    currentDirectoryNodeId: HOME,
    async sendRaw(frame: unknown) {
      if ((frame as Record<string, unknown>)["type"] === "discovery_lookup") {
        const reply = answerDiscovery();
        if (reply) inbound?.(reply);
      }
      return { ok: true as const };
    },
    registerInboundHandler(h: (frame: Record<string, unknown>) => void) {
      inbound = h;
      return () => { inbound = null; };
    },
  };

  const deps = {
    logger,
    sessionNodeManager: {
      getStandingReceiverInfo: () => ({ peerId: "12D3KooWReceiver", addrs: ["/ip4/127.0.0.1/tcp/3"] }),
      getSessionNodePeerId: () => null,
    },
    getKeyProvider: () => ({ async getPublicKey() { return new Uint8Array(32); }, async sign() { return new Uint8Array(64); } }),
    getPersistence: () => ({
      async loadRegistrationState() {
        return { agentId: "a", primaryPubkey: "aa".repeat(32), mlDsaPubkey: "", registeredAt: 0, status: "registered" };
      },
      async listTrustSignalsForPresentation() { return []; },
      async loadOutboundMoniker() { return null; },
    }),
    getAgentSignaling: () => ({ signaling, getNode: () => null }),
    waitForSignalingConnected: async () => true,
    getFailoverEndpoint: async () => null,
    registerSealListeners: () => () => {},
    getManifestVersion: () => 1,
    loadedAgents: [{ name: AGENT, pubkey: "aa".repeat(32) }],
    resolveConsortiumRoster: async () => [{ nodeId: HOME }, { nodeId: "dir-b" }] as never,
    getUnresolvedNodes: () => unresolved,
  } as unknown as OutboundSessionDeps;

  return { negotiator: createOutboundSessions(deps).resolvedSessionNegotiator, events };
}

function negotiate(negotiator: { negotiate: (ctx: never) => Promise<{ ok: boolean; reason?: string; guidance?: string }> }) {
  return negotiator.negotiate({
    agentName: AGENT,
    correlationId: "corr-errstring",
    advertisedAddress: { peerId: "12D3KooWReceiver", addrs: ["/ip4/127.0.0.1/tcp/3"] },
    params: { target_pubkey: TARGET },
  } as never);
}

describe("DOD-M15-ERRSTRING-1: the error names the observation, not a party", () => {
  it("a directory that says ONLINE but names no home does NOT report the counterparty offline", async () => {
    // The contradiction in its own message: reason said offline, guidance said the directory
    // reported them online. An operator acts on the reason and goes to ask the one party whose
    // side is working.
    const { negotiator } = negotiatorWith(() => ({
      type: "discovery_lookup_result",
      state: "online",
      owning_node_ids: [], // online, nobody named
    }));

    const result = await negotiate(negotiator);

    expect(result.ok).toBe(false);
    expect(result.reason, "the counterparty is not the broken thing here").not.toBe("counterparty_offline");
    expect(result.reason).toBe("directory_named_no_home");
    // AFFORDANCE: says where the fault is NOT, so the operator does not spend the call on it.
    expect(result.guidance).toMatch(/nothing for them to fix|not the counterparty being offline/i);
    expect(result.guidance, "and what to actually do").toMatch(/cello_status/);
  }, 30_000);

  it("preserves an UPSTREAM reason instead of overwriting it with a party's state", async () => {
    /**
     * Invariant 3, which is what this line generalises to: a downstream layer never overwrites an
     * upstream descriptive error.
     *
     * Discovery succeeds and names our own node, so the flow proceeds to `session_request`, which
     * the fake never answers. The truthful upstream observation is a TIMEOUT — and it survives all
     * the way out rather than being restated as a claim about whether the counterparty is online.
     * That is the difference between "we did not hear back" and "they are not there".
     */
    const { negotiator } = negotiatorWith(() => ({
      type: "discovery_lookup_result",
      state: "online",
      owning_node_ids: [HOME],
    }));

    const result = await negotiate(negotiator);

    expect(result.ok).toBe(false);
    expect(
      result.reason,
      "a timeout is an observation about OUR wait, not a statement about the counterparty's state",
    ).not.toBe("counterparty_offline");
    expect(result.reason).toBe("timeout");
  }, 60_000);

  it("does NOT rewrite the home node's 'no receiver' into a claim that the peer is offline", async () => {
    /**
     * Review F2, and the reviewer's ruling that this — not the branch I fixed first — is the most
     * likely source of the 2026-08-16 incident.
     *
     * What the home node reports is `targetStreamFound === false`: no live stream registered for
     * that agent. At least four conditions produce it and only one is "they are offline" — the
     * commonest being their receiver's REGISTRATION lapsing on a signaling reconnect, which this
     * daemon's own notes record happening on 46 of 48 reconnects in an hour, while their
     * `cello_status` stayed green throughout.
     *
     * Collapsing that into `counterparty_offline` sends the operator to ask a person whose side is
     * working about a registration on a stream on the directory's side.
     */
    const { negotiator } = negotiatorWith(() => ({
      type: "discovery_lookup_result",
      state: "online",
      owning_node_ids: ["some-other-node"], // cross-node, so the request goes to their home
    }));

    const result = await negotiate(negotiator);

    expect(result.ok).toBe(false);
    expect(
      result.reason,
      "an unregistered receiver is not the same observation as an offline counterparty",
    ).not.toBe("counterparty_offline");
  }, 60_000);

  it("REGRESSION: a directory that genuinely says OFFLINE is still quoted, not second-guessed", async () => {
    // The over-correction this unit must not make. `counterparty_offline` is the right answer when
    // the directory actually reported that state — the defect was returning it when it had not.
    const { negotiator } = negotiatorWith(() => ({
      type: "discovery_lookup_result",
      state: "offline",
      owning_node_ids: [],
    }));

    const result = await negotiate(negotiator);

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("counterparty_offline");
    expect(result.guidance).toMatch(/not currently online/i);
  }, 30_000);

  it("REGRESSION: an unknown agent stays its own reason and is not softened into 'offline'", async () => {
    // A bad address is a different problem with a different action, and it must not retry.
    const { negotiator } = negotiatorWith(() => ({
      type: "discovery_lookup_result",
      state: "unknown_agent",
      owning_node_ids: [],
    }));

    const result = await negotiate(negotiator);

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("unknown_agent");
    expect(result.guidance).toMatch(/verify the pubkey/i);
  }, 30_000);
});

describe("DOD-M15-ERRSTRING-1: a roster below threshold SAYS SO", () => {
  it("names the unreachable nodes and the threshold when the roster is short", async () => {
    /**
     * The DoD line's first clause, and the one this unit had not delivered: *"A roster below
     * threshold says so."*
     *
     * A signing ceremony needs a majority of the declared nodes. When two of five are unreachable,
     * every session failure is very likely a symptom of that — and the operator holding the error
     * had no way to know, because only `cello_status` reported it. The error is what people act on.
     *
     * Appended as CONTEXT, never substituted for the observation: overwriting the observed reason
     * with "roster short" would be this line's own defect pointing the other way.
     */
    const { negotiator } = negotiatorWith(
      () => ({ type: "discovery_lookup_result", state: "online", owning_node_ids: [] }),
      [
        { nodeId: "dir-euc1", reason: "dns_error" },
        { nodeId: "dir-apne1", reason: "timeout" },
      ],
    );

    const result = await negotiate(negotiator);

    expect(result.ok).toBe(false);
    // The OBSERVATION survives — the shortfall is added to it, not instead of it.
    expect(result.reason).toBe("directory_named_no_home");
    // Named nodes and their reasons, not a count the operator has to go and expand.
    expect(result.guidance).toContain("dir-euc1");
    expect(result.guidance).toContain("dns_error");
    // The arithmetic that matters: 2 reachable of 4 declared, threshold 3 — ceremonies cannot run.
    expect(result.guidance).toMatch(/threshold of 3/);
    expect(result.guidance).toMatch(/CANNOT complete/);
  }, 30_000);

  it("says NOTHING about the roster when every node is reachable", async () => {
    // A note that fires on the healthy case is noise, and noise is how a real shortfall gets
    // scrolled past the day it matters.
    const { negotiator } = negotiatorWith(
      () => ({ type: "discovery_lookup_result", state: "online", owning_node_ids: [] }),
      [],
    );

    const result = await negotiate(negotiator);

    expect(result.ok).toBe(false);
    expect(result.guidance).not.toMatch(/unreachable at the last sweep/);
  }, 30_000);
});
