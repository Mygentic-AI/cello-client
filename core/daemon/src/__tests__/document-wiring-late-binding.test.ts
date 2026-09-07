/**
 * The reconcile scheduler is read at CALL TIME, not captured at construction.
 *
 * This exists because 040-DAEMONROOT unit 4 broke it and 5,003 green tests said nothing. The
 * scheduler is built AFTER the document wiring — it consumes the layer's sweep targets — so at
 * construction the binding is `undefined`. The first cut of the extraction passed the value, which
 * captured that `undefined` for the life of the process; `scheduler?.noteRefusal(...)` then became a
 * permanent no-op. Optional chaining made it silent and `| undefined` in the type made it legal.
 *
 * What that costs, in the operator's chair: a counterparty refusing a document exchange is still
 * logged, but the backoff never applies, so the sweep asks again immediately and keeps asking. The
 * scheduler's own notes record the measured version of exactly that state — 321 attempts against two
 * documents in 85 minutes, refused every time, zero successes.
 *
 * Nothing else in the suite drives a peer refusal through the composition root, which is why this
 * test asserts the BINDING rather than the behaviour: it is the property that broke.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

/** Captures the deps `createDocumentWiring` hands to the layer, which is where `onPeerRefusal` lives. */
const captured: { onPeerRefusal?: (o: string, p: string, terminal: boolean) => void } = {};

vi.mock("../document-layer.js", () => ({
  createDocumentLayer: (deps: { onPeerRefusal?: (o: string, p: string, t: boolean) => void }) => {
    captured.onPeerRefusal = deps.onPeerRefusal;
    return { store: {}, notifications: {}, holdersFor: () => [], governanceFrontierFor: () => null };
  },
  agentPublicKeyFromId: (id: string) => id,
}));
vi.mock("../document-delivery-transport.js", () => ({ createDocumentDeliveryTransport: () => ({}) }));

const { createDocumentWiring } = await import("../document-wiring.js");

/** Only the members this path touches; the rest are never reached by `onPeerRefusal`. */
function build(getReconcileScheduler: () => { noteRefusal: (o: string, p: string, t: boolean) => void } | undefined) {
  return createDocumentWiring({
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    // Only what the wiring CALLS while being built. A fuller stub would hide which of these the
    // construction path actually reaches, which is the thing a reader of this test wants to know.
    sessionNodeManager: {
      getDb: () => ({}),
      setOnDocumentFrame: () => {},
      setOnDocumentAck: () => {},
      sendContent: () => {},
      contentHashForSession: () => "",
      appendLeaf: () => {},
    },
    loadedAgents: [],
    keyProviders: new Map(),
    securityGateway: { screenInbound: async () => ({}) },
    celloDir: "/tmp/cello-test",
    deliveryOpens: { begin: () => () => {} },
    pubkeyOfAgent: () => "",
    openSessionFor: async () => ({}),
    perAgentSignaling: new Map(),
    runDiscoveryLookup: async () => ({}),
    getReconcileScheduler,
    notificationDispatcher: { dispatchDocumentWatch: () => {} },
    getCloseSessionHandler: () => undefined,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any);
}

describe("a peer refusal reaches a scheduler that did not exist when the wiring was built", () => {
  beforeEach(() => { captured.onPeerRefusal = undefined; });

  it("resolves the scheduler at CALL time, so one constructed later still receives the refusal", () => {
    // Exactly the daemon's ordering: the binding is empty when the wiring is built.
    let scheduler: { noteRefusal: (o: string, p: string, t: boolean) => void } | undefined;
    build(() => scheduler);
    expect(captured.onPeerRefusal, "the layer was never handed an onPeerRefusal").toBeTypeOf("function");

    const seen: Array<[string, string, boolean]> = [];
    scheduler = { noteRefusal: (o, p, t) => { seen.push([o, p, t]); } };

    captured.onPeerRefusal?.("owner-key", "peer-key", true);

    expect(seen, "the refusal did not reach the scheduler — the backoff is a no-op and the sweep will re-ask immediately")
      .toEqual([["owner-key", "peer-key", true]]);
  });

  it("does not throw when there genuinely is no scheduler", () => {
    build(() => undefined);
    expect(() => captured.onPeerRefusal?.("owner-key", "peer-key", false)).not.toThrow();
  });
});
