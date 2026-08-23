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
    // The node a session DIALS OUT on. Note what this does NOT cover — see the promotion test
    // below, which is the half that matters and which this test was originally used to license.
    const { opts } = await captureNodeOptions({ sessionId: "s2", nodeType: "session" });
    expect(opts["idleConnectionReaper"]).toBeUndefined();
  });

  it("spares the counterparty once the gate names one — the node is REUSED across promotion", async () => {
    /**
     * THE TEST THAT WAS MISSING, and review found the defect by reading the promotion path:
     * `acceptSession` does not build a new node, it moves the SAME `CelloNode` from
     * `#standingReceivers` into `#activeNodes`. So the interval armed here keeps running after
     * promotion, against the session's own counterparty.
     *
     * The earlier "does NOT arm it on a session node" test above was used to license the claim
     * that this cannot happen. It covers the OUTBOUND node type only; the inbound half never goes
     * through that branch. A green test proving less than it looks.
     */
    const gater = new SessionConnectionGater({
      sessionId: "s5",
      allowedPeerId: null,
      logger: silentLogger,
    });
    const { node } = await captureNodeOptions({
      sessionId: "s5",
      nodeType: "standing_receiver",
      connectionGater: gater,
    });
    const setSpared = (node as unknown as { setIdleReaperSpared: ReturnType<typeof vi.fn> })
      .setIdleReaperSpared;
    const isSpared = setSpared.mock.calls[0]![0] as (p: string) => boolean;

    // Unclaimed: nobody is named, so nobody is spared on that basis.
    expect(isSpared("12D3KooWCounterparty")).toBe(false);
    // An offer names the dialer (pre-promotion) — already off-limits from here.
    gater.admitInboundPeer("12D3KooWCounterparty");
    expect(isSpared("12D3KooWCounterparty"), "the admitted dialer was not spared").toBe(true);
    // Promotion narrows to the same peer as the session's counterparty.
    gater.setAllowedPeer("12D3KooWCounterparty");
    expect(
      isSpared("12D3KooWCounterparty"),
      "the session counterparty was not spared — the sweep would hang it up mid-conversation",
    ).toBe(true);
    // And a refused offer returns them to reapable, which is the population this unit exists for.
    gater.closeInbound();
    expect(
      isSpared("12D3KooWCounterparty"),
      "a peer whose offer was withdrawn stayed spared, leaving the reaper with no target at all",
    ).toBe(false);
  });
});

describe("W3: a reap is heard, and a failed reap is not mistaken for a successful one", () => {
  it("logs the reap at WARN with an impact line, and a failure at ERROR", async () => {
    // Invariant 2. The operator's next send returns `no_connection` and
    // `session.transport.redial.unavailable` says "every send parks until they re-establish" —
    // neither names the local timer. This log line is the only thing that does.
    const lines: Array<{ level: string; event: string; fields: Record<string, unknown> }> = [];
    const logger = {
      debug: (event: string, fields: Record<string, unknown>) => { lines.push({ level: "debug", event, fields }); },
      info: () => {},
      warn: (event: string, fields: Record<string, unknown>) => { lines.push({ level: "warn", event, fields }); },
      error: (event: string, fields: Record<string, unknown>) => { lines.push({ level: "error", event, fields }); },
    } as unknown as Logger;

    const transport = await import("@cello-protocol/transport");
    const seen: Array<Record<string, unknown>> = [];
    const spy = vi.spyOn(transport, "createNode");
    spy.mockImplementation(async (opts: Record<string, unknown>) => {
      seen.push(opts);
      return { setIdleReaperSpared: vi.fn(), stop: async () => {} } as never;
    });
    try {
      await new ProductionSessionNodeFactory(logger).createNode({
        sessionId: "s6",
        nodeType: "standing_receiver",
      });
    } finally {
      spy.mockRestore();
    }

    const reaper = seen[0]!["idleConnectionReaper"] as {
      onReaped: (e: { peerId: string; ageMs: number; reason: string; error?: string }) => void;
      onObserved: (c: { total: number; inbound: number; neverSpoke: number; maxConnections: number }) => void;
    };

    reaper.onReaped({ peerId: "12D3KooWGone", ageMs: 91_000, reason: "never_carried_a_stream" });
    const warn = lines.find((l) => l.event === "session.node.connection.reaped");
    expect(warn, "the reap was not logged").toBeDefined();
    expect(warn!.level).toBe("warn");
    expect(warn!.fields["peerId"]).toBe("12D3KooWGone");
    // The impact line is the half an operator acts on, so assert it exists rather than that the
    // call happened — "it did not fail" is the shadow assertion.
    expect(String(warn!.fields["impact"])).toContain("no session state changed");

    // A sweep that could NOT do its job must not read as one that did.
    reaper.onReaped({ peerId: "bad", ageMs: 0, reason: "hangup_failed", error: "invalid_peer_id" });
    const err = lines.find((l) => l.event === "session.node.connection.reap_failed");
    expect(err, "a failed hang-up was silent").toBeDefined();
    expect(err!.level).toBe("error");
    // The NAMED reason survives rather than being flattened into a generic message — the whole
    // point of `invalid_peer_id` existing.
    expect(err!.fields["error"]).toBe("invalid_peer_id");

    reaper.onObserved({ total: 3, inbound: 2, neverSpoke: 1, maxConnections: 300 });
    const census = lines.find((l) => l.event === "transport.connections.observed");
    expect(census, "the connection census was never emitted").toBeDefined();
    expect(census!.fields["neverSpoke"]).toBe(1);
    expect(census!.fields["maxConnections"]).toBe(300);
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
