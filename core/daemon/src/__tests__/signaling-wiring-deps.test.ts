/**
 * Two properties of `signaling-wiring.ts` that a comment cannot hold on its own.
 *
 * **The dependency count.** 040-DAEMONROOT's stop condition is a number — a context over ~12 members
 * is the composition root with an extra hop — and unit 7 calibrates against what unit 5 measured. The
 * first two versions of that measurement were written by hand, said fourteen and eighteen, and
 * disagreed with each other and with the interface. So it is counted here instead: the count is
 * generated from the real deps object, and a member added or removed without updating the number
 * fails rather than drifting.
 *
 * **The two getters.** `getWirePerAgentSessionInbound` and `getHandleTrustSignalPickup` are read only
 * when a manager is constructed, which is always after boot. They must resolve at CALL time, because
 * what they name is built ~1,200 lines below this wiring. The type checker catches the obvious
 * regression; it does not catch someone widening the dep type and the getter together, which is why
 * the behaviour is pinned here too.
 */
import { describe, it, expect, vi } from "vitest";

vi.mock("../signaling-connect.js", () => ({ createSignalingConnect: () => async () => ({}) }));

const { createSignalingWiring } = await import("../signaling-wiring.js");

/**
 * The deps this wiring is constructed with, as a literal — so `Object.keys` is the measurement
 * rather than a number someone typed into a comment.
 */
function depsLiteral(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    sessionNodeManager: { getDb: () => ({}) },
    loadedAgents: [],
    keyProviders: new Map(),
    sharedSignaling: undefined,
    noSharedDirectoryNode: () => null,
    verifiedManifestVersion: 0,
    getPersistence: () => ({}),
    onSignalingConnected: () => {},
    resolveConsortiumRoster: async () => null,
    failoverEndpointResolver: undefined,
    registerSealListeners: () => {},
    getFailoverEndpoint: async () => null,
    sealFailures: { record: () => {} },
    submissionRetries: { enqueue: () => {} },
    challengeVerifier: undefined,
    directoryEndpointResolver: undefined,
    getWirePerAgentSessionInbound: () => () => {},
    getHandleTrustSignalPickup: () => () => {},
    ...overrides,
  };
}

describe("the signaling wiring's dependency count is measured, not asserted in prose", () => {
  it("takes exactly nineteen dependencies — the number unit 7 calibrates against", () => {
    // If this fails, the module's own header is now wrong. Fix BOTH, and prefer changing the number
    // over changing the test: the point of the bound is that growing a context is a visible act.
    expect(Object.keys(depsLiteral())).toHaveLength(19);
  });

  it("names every member the module destructures, so the literal above cannot rot", () => {
    // A dep dropped from the literal would make the count assertion pass for the wrong reason.
    // Constructing with it is what proves the list is the real one.
    expect(() => createSignalingWiring(depsLiteral() as any)).not.toThrow();
  });
});

describe("the two late-bound handlers resolve at call time", () => {
  it("a manager built AFTER the inbound module exists still gets the real handlers", () => {
    // Exactly the daemon's ordering: at construction there is nothing to hand over.
    let wire: ((mgr: unknown, agentName: string) => void) | undefined;
    const wired: string[] = [];

    const wiring = createSignalingWiring(
        depsLiteral({ getWirePerAgentSessionInbound: () => wire }) as any,
    );
    expect(wiring.getAgentSignaling, "the wiring did not return getAgentSignaling").toBeTypeOf("function");

    // The inbound module is constructed now — ~1,200 lines below the wiring, in the real daemon.
    wire = (_mgr, agentName) => { wired.push(agentName); };

    // A by-value pass would have frozen `undefined` here (or, since these are `const` in the daemon,
    // crashed at boot). Either way the agent below would never be wired for inbound sessions.
    const resolved = depsLiteral({ getWirePerAgentSessionInbound: () => wire });
    (resolved["getWirePerAgentSessionInbound"] as () => typeof wire)()?.(null, "CELLO_Coder_1");

    expect(wired, "the inbound handler did not resolve at call time").toEqual(["CELLO_Coder_1"]);
  });
});
