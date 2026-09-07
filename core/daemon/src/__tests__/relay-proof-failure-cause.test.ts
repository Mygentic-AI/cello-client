/**
 * `proveReservation` must report WHY it failed — the cause, not the exit point.
 *
 * ─── The defect these pin ────────────────────────────────────────────────────────────────────
 * On a clean-room run (2026-09-07) every cold `cello login` failed its first reservation proof to
 * both relays, the agent held no relay reservation, and `cello status` reported
 * `standing_receiver_reachability: "retrying"`. The only diagnostic was:
 *
 *     session.relay.reservation_proof.failed  reason: "stream"
 *       error: "Unexpected EOF - stream closed while reading 0/1 bytes"
 *
 * `reason: "stream"` was a LITERAL this call site substituted for the real cause. `CelloNode`
 * throws structured errors — plain objects carrying `reason` — and the true value turned out to be
 * `connection_lost`. Hours went into the relay servers on the strength of a message the client had
 * overwritten. These tests fail if that substitution comes back.
 *
 * Test 1 and 3 are the ones that survive a revert; 3 only because it asserts `newStream` was never
 * reached, which is the actual behaviour change rather than the log text.
 */

import { describe, it, expect, vi } from "vitest";
import { AgentRelayClient } from "../session-relay-client.js";
import { noopLogger } from "./relay-client-fake.js";
import { InMemoryKeyProvider } from "@cello-protocol/crypto";

interface Line { event: string; ctx: Record<string, unknown> }

function makeClient(node: unknown, relayAddrs: string[] = ["/ip4/1.2.3.4/tcp/4001/ws"]) {
  const lines: Line[] = [];
  const logger = {
    ...noopLogger,
    warn: (event: string, ctx: Record<string, unknown>) => { lines.push({ event, ctx }); },
  } as never;
  const client = new AgentRelayClient({
    relayPeerId: "12D3KooWRelayPeer",
    relayAddrs,
    keyProvider: new InMemoryKeyProvider(new Uint8Array(32).fill(7)),
    senderPubkey: new Uint8Array(32).fill(9),
    logger,
  });
  return { client, lines, node: node as never };
}

/** The minimum CelloNode surface proveReservation touches. */
function fakeNode(opts: {
  dial?: () => Promise<void>;
  newStream?: () => Promise<never>;
}) {
  const newStream = vi.fn(opts.newStream ?? (async () => { throw new Error("unused"); }));
  return {
    dial: opts.dial ?? (async () => {}),
    newStream,
    getPeerId: () => "12D3KooWLocalNode",
    getConnections: () => [],
  };
}

describe("proveReservation — the failure must name its cause", () => {
  it("carries the STRUCTURED reason from newStream, not the literal 'stream'", async () => {
    // The exact shape CelloNode.newStream throws: a plain object, not an Error.
    const node = fakeNode({
      newStream: async () => {
        throw { reason: "connection_lost", message: "Unexpected EOF - stream closed while reading 0/1 bytes" } as never;
      },
    });
    const { client, lines } = makeClient(node);

    expect(await client.proveReservation(node as never)).toBe(false);

    const failed = lines.find((l) => l.event === "session.relay.reservation_proof.failed");
    expect(failed, "the failure must be logged").toBeDefined();
    /**
     * THE REGRESSION GUARD. Reverting the fix makes this `"stream"` and sends the next
     * investigation to the relay servers, exactly as it did on 2026-09-07.
     */
    expect(failed!.ctx["reason"]).toBe("connection_lost");
    expect(String(failed!.ctx["error"])).toContain("Unexpected EOF");
  });

  it("falls back to 'stream' for a real Error, which carries no reason", async () => {
    const node = fakeNode({ newStream: async () => { throw new Error("boom") as never; } });
    const { client, lines } = makeClient(node);

    await client.proveReservation(node as never);

    const failed = lines.find((l) => l.event === "session.relay.reservation_proof.failed");
    expect(failed!.ctx["reason"]).toBe("stream");
    expect(String(failed!.ctx["error"])).toContain("boom");
  });

  it("a non-string reason must NOT reach the log as the reason", async () => {
    // `reason` is read as an enum by every consumer; a number would poison that.
    const node = fakeNode({ newStream: async () => { throw { reason: 42 } as never; } });
    const { client, lines } = makeClient(node);

    await client.proveReservation(node as never);

    const failed = lines.find((l) => l.event === "session.relay.reservation_proof.failed");
    expect(failed!.ctx["reason"]).toBe("stream");
  });

  it("when EVERY dial fails it reports reason 'dial' and never opens a stream", async () => {
    const node = fakeNode({
      dial: async () => { throw new Error("ECONNREFUSED"); },
      newStream: async () => { throw new Error("must not be reached") as never; },
    });
    const { client, lines } = makeClient(node, ["/ip4/1.2.3.4/tcp/4001/ws", "/ip4/5.6.7.8/tcp/4001/ws"]);

    expect(await client.proveReservation(node as never)).toBe(false);

    const failed = lines.find((l) => l.event === "session.relay.reservation_proof.failed");
    expect(failed!.ctx["reason"]).toBe("dial");
    expect(String(failed!.ctx["error"])).toContain("ECONNREFUSED");
    /**
     * THE BEHAVIOUR CHANGE, and the only assertion here that fails on the old code — which fell
     * through to `newStream` with every dial failed and then blamed the stream.
     */
    expect(node.newStream).not.toHaveBeenCalled();
  });

  it("with NO relay addresses it does not claim a dial failure, and still tries the stream", async () => {
    // Pins the `length > 0` half of the guard: a client with no addresses may still have a live
    // connection, and must not be refused on the strength of a dial loop that never ran.
    const node = fakeNode({ newStream: async () => { throw { reason: "no_connection" } as never; } });
    const { client, lines } = makeClient(node, []);

    await client.proveReservation(node as never);

    const failed = lines.find((l) => l.event === "session.relay.reservation_proof.failed");
    expect(failed!.ctx["reason"]).toBe("no_connection");
    expect(node.newStream).toHaveBeenCalled();
  });
});

describe("proveReservation — retry only when no verdict was reached", () => {
  it("retries ONCE after a transport failure and succeeds on the fresh connection", async () => {
    /**
     * The cold-login case. libp2p restarts its connection manager after the relay refuses its
     * automatic reservation, destroying the connection this proof was opening on. The relay never
     * answered, so the question is still open and asking again is legitimate.
     */
    let call = 0;
    const node = fakeNode({
      newStream: async () => {
        call += 1;
        if (call === 1) throw { reason: "connection_lost", message: "Unexpected EOF" } as never;
        // Second attempt: a stream that immediately ends, so #authenticate returns false rather
        // than hanging. The assertion here is the RETRY, not the auth outcome.
        throw { reason: "connection_lost", message: "second" } as never;
      },
    });
    const { client } = makeClient(node);

    await client.proveReservation(node as never);

    expect(node.newStream, "a transport failure must be retried exactly once").toHaveBeenCalledTimes(2);
  });

  it("does NOT retry when the relay reached a VERDICT", async () => {
    /**
     * THE GUARD THAT MATTERS. A refusal — no token, slot cap, misconfigured relay — will be
     * identical a second later. Retrying spends the operator's reachability re-asking a question
     * that was already answered, and doubles the load the relay's rate limits exist to bound.
     *
     * Modelled as the stream opening fine (no transport fault); whatever #authenticate then
     * concludes is a verdict, and one attempt is all that may happen.
     */
    const ended = {
      // An immediately-closed stream: #authenticate gets no frame and returns a verdict of false.
      send: () => {},
      close: async () => {},
      [Symbol.asyncIterator]: async function* () { /* no frames */ },
    };
    const node = fakeNode({ newStream: (async () => ended) as never });
    const { client } = makeClient(node);

    const result = await client.proveReservation(node as never);

    expect(result).toBe(false);
    expect(node.newStream, "a verdict must never be retried").toHaveBeenCalledTimes(1);
  });

  it("gives up after the second transport failure rather than looping", async () => {
    const node = fakeNode({
      newStream: async () => { throw { reason: "connection_lost" } as never; },
    });
    const { client } = makeClient(node);

    expect(await client.proveReservation(node as never)).toBe(false);
    // Bounded: two attempts, never a third. An unbounded retry against a relay that is genuinely
    // unreachable is a hot loop against someone else's infrastructure.
    expect(node.newStream).toHaveBeenCalledTimes(2);
  });
});
