/**
 * DOD-M15-IDLE-CONNS-1 — the DAEMON half: does anything actually turn the reaper on?
 *
 * ─── WHY THIS FILE EXISTS SEPARATELY FROM THE TRANSPORT TESTS ──────────────────────────────────
 *
 * The transport suite proves the sweep works when a node is built with it. It cannot prove the
 * daemon ever builds one that way. That seam — a green module with nothing showing production
 * calls it — has now escaped in FOUR consecutive units of this milestone (the roster sweep, its
 * probe budget, the manifest validity tick, and the seal-failure writer), and in the last of them
 * the author wrote a docstring naming the previous three and then made the same mistake one layer
 * up.
 *
 * Mutation testing on the transport half already caught one live instance of exactly this: with
 * the `connectionManager` block deleted from the `createLibp2p` call, eleven tests stayed green
 * because they asserted what the node REPORTED rather than what libp2p RECEIVED.
 *
 * So these assert the two things the factory decides, and nothing else:
 *   W1 — a standing receiver gets a reaper; a session node does not.
 *   W2 — the receiver's reaper spares whatever the gater's outbound allowlist names, which is what
 *        stops it hanging up the relay the agent's inbound reachability depends on.
 */
import { describe, it, expect, vi } from "vitest";
import { ProductionSessionNodeFactory } from "../daemon.js";
import { SessionConnectionGater } from "../session-connection-gater.js";
import type { Logger } from "../types.js";

const silentLogger: Logger = {
  debug: () => {}, info: () => {}, warn: () => {}, error: () => {},
} as unknown as Logger;

/**
 * Spy on the transport's createNode WITHOUT stubbing the node itself.
 *
 * The hollow-test question "what did I stub, and does the property live in the stub?" applies
 * directly: if this replaced CelloNode wholesale, every assertion below would be about the fake.
 * So the real node is built and only its OPTIONS are captured — the factory's decision is the
 * thing under test.
 */
async function captureNodeOptions(config: Parameters<ProductionSessionNodeFactory["createNode"]>[0]) {
  const transport = await import("@cello-protocol/transport");
  const seen: Array<Record<string, unknown>> = [];
  const spy = vi.spyOn(transport, "createNode");
  spy.mockImplementation(async (opts: Record<string, unknown>) => {
    seen.push(opts);
    return {
      setIdleReaperSpared: vi.fn(),
      stop: async () => {},
    } as never;
  });
  try {
    const node = await new ProductionSessionNodeFactory().createNode(config);
    return { opts: seen[0]!, node };
  } finally {
    spy.mockRestore();
  }
}

describe("W1: only the standing receiver runs the idle sweep", () => {
  it("arms the reaper on a standing receiver", async () => {
    const { opts } = await captureNodeOptions({ sessionId: "s1", nodeType: "standing_receiver" });
    // Name the value. "It did not fail" is the shadow assertion this milestone keeps catching:
    // asserting merely that createNode was called would pass with the option absent.
    expect(opts["idleConnectionReaper"]).toBeDefined();
  });

  it("does NOT arm it on an ephemeral session node", async () => {
    // A session node's counterparty is speaking to it by definition. Sweeping there would hang up
    // a live conversation's transport on a timer that has nothing to do with the conversation.
    const { opts } = await captureNodeOptions({ sessionId: "s2", nodeType: "session" });
    expect(opts["idleConnectionReaper"]).toBeUndefined();
  });
});

describe("W2: the receiver's reaper spares the peers reachability depends on", () => {
  it("passes a predicate that spares the gater's outbound allowlist", async () => {
    const gater = new SessionConnectionGater({
      sessionId: "s3",
      allowedPeerId: null,
      logger: silentLogger,
    });
    gater.setAllowedOutboundPeer("12D3KooWRelay");

    const { node } = await captureNodeOptions({
      sessionId: "s3",
      nodeType: "standing_receiver",
      connectionGater: gater,
    });

    const setSpared = (node as unknown as { setIdleReaperSpared: ReturnType<typeof vi.fn> })
      .setIdleReaperSpared;
    expect(setSpared, "the factory never told the node what to spare").toHaveBeenCalledTimes(1);

    const isSpared = setSpared.mock.calls[0]![0] as (p: string) => boolean;
    // THE CLAUSE THIS UNIT WOULD MOST LIKELY GET WRONG. A relay reservation carries no stream
    // between refreshes, so it looks exactly like the silent peer the sweep hunts. Reaping it
    // costs the agent every NAT'd inbound session, silently.
    expect(isSpared("12D3KooWRelay"), "the reserved relay was not spared").toBe(true);
    expect(isSpared("12D3KooWStranger"), "an unrelated peer was spared").toBe(false);
  });

  it("reads the allowlist LIVE, so a relay added after node creation is still spared", async () => {
    // Captured-once would spare the relays known at construction and reap the ones taken later —
    // and reservations are lost and retaken routinely (2,675 `reservation.lost` in one daemon's
    // log, DOD-M15-MULTIRELAY-1). A predicate frozen at build time is wrong within minutes.
    const gater = new SessionConnectionGater({
      sessionId: "s4",
      allowedPeerId: null,
      logger: silentLogger,
    });
    const { node } = await captureNodeOptions({
      sessionId: "s4",
      nodeType: "standing_receiver",
      connectionGater: gater,
    });
    const setSpared = (node as unknown as { setIdleReaperSpared: ReturnType<typeof vi.fn> })
      .setIdleReaperSpared;
    const isSpared = setSpared.mock.calls[0]![0] as (p: string) => boolean;

    expect(isSpared("12D3KooWLateRelay")).toBe(false);
    gater.setAllowedOutboundPeer("12D3KooWLateRelay");
    expect(isSpared("12D3KooWLateRelay"), "the predicate captured the allowlist instead of reading it").toBe(true);
  });
});
