/**
 * DOD-M15-PARKCONN-1 — a message to an offline counterparty stops being a coin flip.
 *
 * From the operator's chair: they message someone whose agent is offline — exactly what park is
 * for — and sometimes it parks and sometimes it fails with `No open connection to peer 12D3Koo…`.
 * Same action, two outcomes, nothing telling them which one they got or why.
 *
 * The reason nobody could tell was OUR OWN CODE deleting it. `ContentParkClient.#open` dials the
 * relay first and threw every dial failure away in an empty `catch`, so by the time `newStream`
 * reported `no_connection` the one fact that explains it — WHY there was no connection — had
 * already been discarded. The throw site's own comment says `no_connection` is "the one condition a
 * dial fixes"; a dial HAD run, and its verdict was gone.
 *
 * Pinned here:
 *  A1 — every address fails → the error and the log carry each (addr, reason).
 *  A2 — a dial SUCCEEDS and the connection is gone anyway → distinguished from A1, because the two
 *       have different causes and only one of them is a dial problem.
 *  A3 — a dial fails and the stream opens anyway → still a NON-EVENT. The best-effort loop is
 *       correct and must not start shouting about addresses that did not matter.
 *  B1 — the deposit IPC handler REFUSES (`{ok:false, reason, guidance}`) instead of throwing, so an
 *       unreachable relay stops surfacing as `internal_error` / "An unexpected error occurred."
 *  B2 — the handler logs its result ONCE, with `ok` and `reason` — the line 019-PARKERROR went
 *       looking for and did not find, because this handler logged nothing at all.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import type { CelloNode } from "@cello-protocol/transport";
import { ContentParkClient, ContentParkUnreachableError } from "../content-park-client.js";
import { createContentPark } from "../content-park.js";
import type { IpcHandler, Logger } from "../types.js";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context: context ?? {} }); },
    info(event, context) { events.push({ level: "info", event, context: context ?? {} }); },
    warn(event, context) { events.push({ level: "warn", event, context: context ?? {} }); },
    error(event, context) { events.push({ level: "error", event, context: context ?? {} }); },
  };
  return { logger, events };
}

const RELAY_PEER = "12D3KooWDQJ8kLzL9CTM2NUrzQS34tECvNPGtSvMAkFn35YwoJtM";
const ADDR_A = `/ip4/127.0.0.1/tcp/4001/p2p/${RELAY_PEER}`;
const ADDR_B = `/ip4/127.0.0.1/tcp/4002/p2p/${RELAY_PEER}`;

/**
 * The transport rejects with PLAIN OBJECT LITERALS — `{ reason, peerId, message }` — not `Error`s
 * (`core/transport/src/node.ts` newStream). `instanceof Error` is false on them and `String(err)`
 * gives "[object Object]", which is the shape that made this defect unreadable for a fortnight, so
 * the fixture uses it verbatim rather than a friendlier `new Error()`.
 */
const noConnection = () => ({
  reason: "no_connection",
  peerId: RELAY_PEER,
  message: `No open connection to peer ${RELAY_PEER}`,
});

function fakeNode(opts: {
  dial: (addr: string) => Promise<void>;
  newStream: () => Promise<unknown>;
}): CelloNode {
  return {
    dial: (addr: string) => opts.dial(addr),
    newStream: () => opts.newStream(),
  } as unknown as CelloNode;
}

/** A stream that swallows everything — enough for `deposit()` to get past `#open`. */
function inertStream(): unknown {
  return {
    send() {},
    async close() {},
    abort() {},
    status: "open",
    [Symbol.asyncIterator]() { return { async next() { return { done: true, value: undefined }; } }; },
  };
}

describe("A: #open stops eating the dial failure", () => {
  it("A1: every address fails → the error and the log carry each (addr, reason)", async () => {
    const { logger, events } = makeLogger();
    const client = new ContentParkClient({ relayPeerId: RELAY_PEER, relayAddrs: [ADDR_A, ADDR_B], logger });
    const node = fakeNode({
      dial: async (addr) => { throw { reason: "dial_refused", message: `connect ECONNREFUSED on ${addr}` }; },
      newStream: async () => { throw noConnection(); },
    });

    const err = await client
      .deposit(node, { recipientPubkey: randomBytes(32), contentHash: randomBytes(32), sessionId: randomBytes(16), ciphertext: randomBytes(8) })
      .then(() => null, (e: unknown) => e);

    expect(err, "an unreachable relay throws the typed error, not the bare transport literal").toBeInstanceOf(ContentParkUnreachableError);
    const unreachable = err as ContentParkUnreachableError;
    expect(unreachable.reason).toBe("no_connection");
    expect(unreachable.dialFailures.map((f) => f.addr)).toEqual([ADDR_A, ADDR_B]);
    expect(unreachable.dialFailures[0]!.error).toContain("ECONNREFUSED");
    // The MESSAGE alone has to carry it: extractErrorMessage is all most callers ever read.
    expect(unreachable.message).toContain("ECONNREFUSED");
    expect(unreachable.message).not.toContain("[object Object]");

    const open = events.find((e) => e.event === "content.park.open.failed");
    expect(open, "the dial failures reach the log, not only the thrown value").toBeDefined();
    expect(open!.level).toBe("warn");
    expect(open!.context["reason"]).toBe("no_connection");
    expect(JSON.stringify(open!.context["dialFailures"])).toContain("ECONNREFUSED");
    expect(JSON.stringify(open!.context)).not.toContain("[object Object]");
    // A1 and A2 must be told apart by the record, not by the reader's guess.
    expect(String(open!.context["dialOutcome"])).toBe("all_addresses_failed");
  });

  it("A2b: NO relay address configured is its own cause, not 'every address failed'", async () => {
    // Review: deleting the `no_address_configured` arm left the ternary yielding
    // `all_addresses_failed`, so the log claimed "every relay address failed to dial" about ZERO
    // addresses — a confident sentence about something that never happened. No test passed `[]`.
    const { logger, events } = makeLogger();
    const client = new ContentParkClient({ relayPeerId: RELAY_PEER, relayAddrs: [], logger });
    let dials = 0;
    const node = fakeNode({
      dial: async () => { dials++; },
      newStream: async () => { throw noConnection(); },
    });

    const err = await client
      .deposit(node, { recipientPubkey: randomBytes(32), contentHash: randomBytes(32), sessionId: randomBytes(16), ciphertext: randomBytes(8) })
      .then(() => null, (e: unknown) => e);

    expect(err).toBeInstanceOf(ContentParkUnreachableError);
    expect(dials, "with no address there is nothing to dial").toBe(0);
    const open = events.find((e) => e.event === "content.park.open.failed");
    expect(String(open!.context["dialOutcome"])).toBe("no_address_configured");
    expect(String(open!.context["impact"])).toContain("no relay address was configured");
  });

  it("A2: a dial SUCCEEDS and the connection is gone anyway → recorded as a different cause", async () => {
    const { logger, events } = makeLogger();
    const client = new ContentParkClient({ relayPeerId: RELAY_PEER, relayAddrs: [ADDR_A, ADDR_B], logger });
    const node = fakeNode({
      dial: async () => {},
      newStream: async () => { throw noConnection(); },
    });

    const err = await client
      .deposit(node, { recipientPubkey: randomBytes(32), contentHash: randomBytes(32), sessionId: randomBytes(16), ciphertext: randomBytes(8) })
      .then(() => null, (e: unknown) => e);

    expect(err).toBeInstanceOf(ContentParkUnreachableError);
    expect((err as ContentParkUnreachableError).dialFailures).toEqual([]);
    const open = events.find((e) => e.event === "content.park.open.failed");
    expect(open).toBeDefined();
    expect(String(open!.context["dialOutcome"])).toBe("dialed_then_lost");
  });

  /**
   * ⚠️ **A GUARD, NOT COVERAGE — and it FAILS THE REVERT TEST, which is why the name says so.**
   *
   * Every assertion below passes on the tree BEFORE this unit: the old `#open` emitted no
   * `content.park.open.failed` at all, both addresses were already dialled, and `ok` was already
   * false. So it proves nothing about the fix. It is here to stop the fix growing louder later —
   * the natural next change is to report the dial failures unconditionally, and that would make a
   * dial nobody needed into an error line an operator has to dismiss.
   *
   * Recorded explicitly because a passing test sitting beside a fix reads as proof of the fix, and
   * this one is not.
   */
  it("A3 (guard, not coverage — passes pre-fix by construction): a dial fails and the stream opens anyway → still a non-event", async () => {
    const { logger, events } = makeLogger();
    const client = new ContentParkClient({ relayPeerId: RELAY_PEER, relayAddrs: [ADDR_A, ADDR_B], logger });
    const dialed: string[] = [];
    const node = fakeNode({
      dial: async (addr) => {
        dialed.push(addr);
        if (addr === ADDR_A) throw { reason: "dial_refused", message: "first address is stale" };
      },
      newStream: async () => inertStream(),
    });

    // No ack comes back from the inert stream, so the deposit reports `no_deposit_ack` — it did NOT
    // fail to open, which is the point: `#open` succeeded and must have said nothing.
    const res = await client.deposit(node, { recipientPubkey: randomBytes(32), contentHash: randomBytes(32), sessionId: randomBytes(16), ciphertext: randomBytes(8) });
    expect(res.ok).toBe(false);
    expect(dialed).toEqual([ADDR_A, ADDR_B]);
    expect(events.find((e) => e.event === "content.park.open.failed"), "a dial that did not matter must stay quiet").toBeUndefined();
  });
});

describe("B: the deposit handler refuses like its siblings", () => {
  function handlersFor(depositImpl: () => Promise<{ ok: boolean; reason?: string }>): { handlers: Map<string, IpcHandler>; events: LogEvent[] } {
    const { logger, events } = makeLogger();
    const park = createContentPark({
      logger,
      sessionNodeManager: { getStandingReceiverNode: () => fakeNode({ dial: async () => {}, newStream: async () => inertStream() }) } as never,
      agents: [{ name: "alice", state: "online", pubkey: "aa".repeat(32) }] as never,
      getKeyProvider: () => undefined,
      securityGateway: { screenInbound: async () => ({ verdict: "allow" }), screenOutbound: async () => ({ verdict: "allow" }) } as never,
      makeContentParkClient: () => ({ deposit: depositImpl }) as never,
    });
    const handlers = new Map<string, IpcHandler>();
    park.registerHandlers(handlers);
    return { handlers, events };
  }

  /** The RAW (`ciphertext:`) deposit shape — it needs no signer, so B is about the transport only. */
  const params = {
    relayMultiaddr: ADDR_A,
    recipientPubkey: "bb".repeat(32),
    contentHash: "cc".repeat(32),
    sessionId: "dd".repeat(16),
    ciphertext: "ee".repeat(8),
  };

  it("B1: an unreachable relay is REFUSED, not thrown — no `internal_error`, and the cause survives", async () => {
    const { handlers, events } = handlersFor(async () => {
      throw new ContentParkUnreachableError({
        reason: "no_connection",
        relayPeerId: RELAY_PEER,
        dialFailures: [{ addr: ADDR_A, error: "connect ECONNREFUSED 127.0.0.1:4001" }],
        cause: `No open connection to peer ${RELAY_PEER}`,
      });
    });

    const res = (await handlers.get("content_park_deposit")!(params, "c1")) as {
      ok?: boolean; reason?: string; guidance?: string; dialFailures?: Array<{ addr: string; error: string }>;
    };

    expect(res.ok, "the handler returns a refusal instead of throwing into internal_error").toBe(false);
    expect(res.reason).toBe("relay_unreachable:no_connection");
    // Invariant 4 — a refusal carries its next step, and the verb has to be real.
    expect(res.guidance, "the refusal names what to do next").toBeTruthy();
    expect(res.guidance).toContain("cello_initiate_session");
    expect(res.guidance).not.toContain("An unexpected error occurred");
    // DoD 1: recoverable from the RESPONSE as well as the log.
    expect(JSON.stringify(res.dialFailures)).toContain("ECONNREFUSED");

    const result = events.filter((e) => e.event === "content.park.deposit.ipc.result");
    expect(result, "exactly one result line").toHaveLength(1);
    expect(result[0]!.context["ok"]).toBe(false);
    expect(result[0]!.context["reason"]).toBe("relay_unreachable:no_connection");
  });

  it("B2: the success path logs the same single result line, carrying ok and reason", async () => {
    const { handlers, events } = handlersFor(async () => ({ ok: true }));

    const res = (await handlers.get("content_park_deposit")!(params, "c1")) as { ok?: boolean };
    expect(res.ok).toBe(true);

    const result = events.filter((e) => e.event === "content.park.deposit.ipc.result");
    expect(result, "the handler that logged NOTHING AT ALL now logs its result once").toHaveLength(1);
    expect(result[0]!.context["ok"]).toBe(true);
    expect(result[0]!.context["reason"]).toBeUndefined();
  });

  /**
   * C — the OTHER face of the coin flip, measured on the live spine on 2026-09-04.
   *
   * Two runs of DOD-MSG-7 minutes apart refused for two different reasons, and the second was not a
   * transport failure at all: `standing_receiver_unavailable`. That branch already returned a
   * refusal — the spine test was discarding it — and it returned the EXIT-POINT LABEL, the one
   * `standingReceiverAbsenceReason()` was added to replace after it misnamed a live incident 102
   * times. `recoverParkedFromRelay` has named the cause since M12-P12; this handler never did.
   *
   * The four causes demand opposite responses, which is why one label for all four is not a detail:
   * "still being built" clears on a retry, "agent offline" never does.
   */
  function handlersWithoutReceiver(absence: string, agentNames: string[]): { handlers: Map<string, IpcHandler>; events: LogEvent[] } {
    const { logger, events } = makeLogger();
    const park = createContentPark({
      logger,
      sessionNodeManager: {
        getStandingReceiverNode: () => undefined,
        standingReceiverAbsenceReason: () => absence,
      } as never,
      agents: agentNames.map((name) => ({ name, state: "online", pubkey: "aa".repeat(32) })) as never,
      getKeyProvider: () => undefined,
      securityGateway: { screenInbound: async () => ({ verdict: "allow" }), screenOutbound: async () => ({ verdict: "allow" }) } as never,
      makeContentParkClient: () => ({ deposit: async () => ({ ok: true }) }) as never,
    });
    const handlers = new Map<string, IpcHandler>();
    park.registerHandlers(handlers);
    return { handlers, events };
  }

  it("C1: no standing receiver names WHICH of the four causes, not the label that stood for all of them", async () => {
    const { handlers, events } = handlersWithoutReceiver("standing_receiver_creating", ["alice"]);

    const res = (await handlers.get("content_park_deposit")!({ ...params, senderAgentName: "alice" }, "c1")) as {
      ok?: boolean; reason?: string; cause?: string; guidance?: string;
    };

    expect(res.ok).toBe(false);
    // The wire reason is UNCHANGED — a caller matching on it keeps working; the cause rides alongside.
    expect(res.reason).toBe("standing_receiver_unavailable");
    expect(res.cause).toBe("standing_receiver_creating");
    expect(res.guidance).toContain("retry");
    expect(events.filter((e) => e.event === "content.park.deposit.ipc.result")[0]!.context["cause"]).toBe("standing_receiver_creating");
  });

  it("C2: an OFFLINE agent is told to start it — the cause that a retry never fixes", async () => {
    const { handlers } = handlersWithoutReceiver("agent_offline", ["alice"]);

    const res = (await handlers.get("content_park_deposit")!({ ...params, senderAgentName: "alice" }, "c1")) as {
      cause?: string; guidance?: string;
    };
    expect(res.cause).toBe("agent_offline");
    // Invariant 4: the verb has to be real and reachable from where the caller stands.
    expect(res.guidance).toContain("cello_start_agent");
  });

  it("C3: with several agents and no name, it says it cannot tell rather than picking one", async () => {
    const { handlers } = handlersWithoutReceiver("agent_offline", ["alice", "bob"]);

    const res = (await handlers.get("content_park_deposit")!(params, "c1")) as { cause?: string; guidance?: string };
    // Guessing an agent would report a cause about the WRONG one — a confident wrong answer.
    expect(res.cause).toBe("unknown_agent");
    expect(res.guidance).toContain("senderAgentName");
  });

  /**
   * D — **ONE STREAM FAILURE IS SIX FAULTS, AND ONLY TWO ARE ABOUT REACHING THE RELAY** (review
   * HIGH-1).
   *
   * `#open` wraps every `newStream` rejection, so the handler received `invalid_peer_id` (a
   * malformed ARGUMENT), `node_stopped` (THIS daemon's transport) and `protocol_not_supported` (the
   * connection worked; the relay does not speak content-park) and told the operator, for all three,
   * that the relay could not be reached and to retry once it is up. That is the substitution this
   * milestone is named for, minted at the mapping site this unit added.
   */
  const unreachable = (reason: string) =>
    new ContentParkUnreachableError({ reason, relayPeerId: RELAY_PEER, dialFailures: [], cause: `transport said ${reason}` });

  it.each([
    ["no_connection", "relay_unreachable:no_connection", "retry once the relay is up", "Retry once the relay is up"],
    ["connection_lost", "relay_unreachable:connection_lost", "retry once the relay is up", "Retry once the relay is up"],
    ["invalid_peer_id", "relay_address_invalid", "the argument, not the network", "retrying will not help"],
    ["node_stopped", "daemon_transport_stopped", "this daemon, not the relay", "This is local"],
    ["protocol_not_supported", "relay_protocol_unsupported", "version skew, not an outage", "version skew"],
    ["limited_connection_refused", "relay_limited_connection", "a defect on this side", "defect on this side"],
    ["something_new", "park_stream_failed:something_new", "no reachability claim for an unknown reason", "specific remedy"],
  ])("D: %s → %s (%s)", async (transportReason, expectedReason, _why, guidanceSubstring) => {
    const { handlers } = handlersFor(async () => { throw unreachable(transportReason); });

    const res = (await handlers.get("content_park_deposit")!(params, "c1")) as { ok?: boolean; reason?: string; guidance?: string };

    expect(res.ok).toBe(false);
    expect(res.reason).toBe(expectedReason);
    expect(res.guidance).toContain(guidanceSubstring);
    // The three non-reachability faults must NOT be dressed as one.
    if (!expectedReason.startsWith("relay_unreachable")) {
      expect(res.reason, "a non-reachability fault must not carry the reachability label").not.toContain("relay_unreachable");
      expect(res.guidance, "…nor the reachability remedy").not.toContain("Retry once the relay is up");
    }
  });

  it("D8: a malformed /p2p/ segment is refused BEFORE a dial, not reported as an unreachable relay", async () => {
    // Defence in depth on the cheapest fault: `parseRelayPeer` accepted anything after `/p2p/`, so a
    // truncated paste only failed four layers down in `newStream`.
    let dialed = false;
    const { handlers } = handlersFor(async () => { dialed = true; return { ok: true }; });

    const res = (await handlers.get("content_park_deposit")!(
      { ...params, relayMultiaddr: "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWDQJ8" },
      "c1",
    )) as { ok?: boolean; reason?: string; guidance?: string };

    expect(res.ok).toBe(false);
    expect(res.reason).toBe("missing_params");
    expect(res.guidance).toContain("/p2p/");
    expect(dialed, "nothing is dialled for an address that cannot name a peer").toBe(false);
  });

  it("D9: a CIRCUIT relay address resolves to the RELAY, not to `<relay>/p2p-circuit`", async () => {
    // The old extraction took everything after the first `/p2p/`, so a circuit address produced a
    // "peer id" with a path glued to it that only `newStream` rejected. Taking the segment is both
    // more correct and what stops the shape check above refusing a legitimate address.
    const { handlers } = handlersFor(async () => ({ ok: true }));
    const res = (await handlers.get("content_park_deposit")!(
      { ...params, relayMultiaddr: `/ip4/127.0.0.1/tcp/4001/p2p/${RELAY_PEER}/p2p-circuit/p2p/${RELAY_PEER}` },
      "c1",
    )) as { ok?: boolean; reason?: string };
    expect(res.ok, "a circuit address is a legitimate address, not a malformed one").toBe(true);
  });

  it("B4: EVERY refusal is logged, not only the two that reach the relay", async () => {
    // Review MEDIUM-3: eleven exits returned in silence, including `agent_not_found` and
    // `session_not_found` — both live spine-failure shapes. This is the same hole 019-PARKERROR
    // fell into, in this very handler, for a different reason.
    for (const [label, p] of [
      ["missing_params", { ...params, contentHash: "zz" }],
      ["conflicting_params", { ...params, content: "aabb" }],
      ["unknown_content_hash_alg", { ...params, ciphertext: undefined, content: "aabb", contentHashAlg: "sha3-nope" }],
    ] as const) {
      const { handlers, events } = handlersFor(async () => ({ ok: true }));
      const res = (await handlers.get("content_park_deposit")!(p as Record<string, unknown>, "c1")) as { ok?: boolean; reason?: string };
      expect(res.ok, label).toBe(false);
      const lines = events.filter((e) => e.event === "content.park.deposit.ipc.result");
      expect(lines, `${label} must be logged`).toHaveLength(1);
      expect(lines[0]!.context["ok"]).toBe(false);
      expect(lines[0]!.context["reason"]).toBe(res.reason);
      // Correlatable: the line names WHICH deposit, read off the caller's own params.
      expect(lines[0]!.context["relayMultiaddr"]).toBe(ADDR_A);
    }
  });

  it("B5: the relay's retryAfterMs reaches the log, not only the response", async () => {
    // Review LOW-8: DOD-M15-RELAYABUSE-1 went to some length to give that number a reader; an
    // aggregated log that drops it cannot say when a throttled deposit clears.
    const { handlers, events } = handlersFor(async () => ({ ok: false, reason: "rate_limited", retryAfterMs: 45_000 }));
    await handlers.get("content_park_deposit")!(params, "c1");
    expect(events.filter((e) => e.event === "content.park.deposit.ipc.result")[0]!.context["retryAfterMs"]).toBe(45_000);
  });

  /**
   * E — **`#open` IS SHARED, SO THE REFUSAL HAS TO BE** (review MEDIUM-2).
   *
   * The deposit handler was fixed and its two siblings were not, so an unreachable relay still
   * reached the operator as `internal_error` + "An unexpected error occurred. Check daemon logs for
   * details." one handler over — on `content_park_recover`, which is one of the three failures this
   * order was written from. A mutation restoring the rethrow survived every test until these.
   */
  const RECIPIENT = "aa".repeat(32);
  function parkFor(clientImpl: Record<string, unknown>): { handlers: Map<string, IpcHandler>; events: LogEvent[] } {
    const { logger, events } = makeLogger();
    const park = createContentPark({
      logger,
      sessionNodeManager: {
        getStandingReceiverNode: () => fakeNode({ dial: async () => {}, newStream: async () => inertStream() }),
        standingReceiverAbsenceReason: () => "no_standing_receiver",
      } as never,
      agents: [{ name: "alice", state: "online", pubkey: RECIPIENT }] as never,
      getKeyProvider: () => ({ sign: async () => new Uint8Array(64), openContentSeal: async () => null }) as never,
      securityGateway: { screenInbound: async () => ({ verdict: "allow" }), screenOutbound: async () => ({ verdict: "allow" }) } as never,
      makeContentParkClient: () => clientImpl as never,
    });
    const handlers = new Map<string, IpcHandler>();
    park.registerHandlers(handlers);
    return { handlers, events };
  }

  it("E1: content_park_pull maps the transport wrap instead of throwing into internal_error", async () => {
    const { handlers } = parkFor({
      pull: async () => { throw unreachable("no_connection"); },
    });

    const res = (await handlers.get("content_park_pull")!(
      { relayMultiaddr: ADDR_A, recipientPubkey: RECIPIENT }, "c1",
    )) as { ok?: boolean; reason?: string; guidance?: string };

    expect(res.ok).toBe(false);
    expect(res.reason).toBe("relay_unreachable:no_connection");
    expect(res.guidance).toContain("cello_initiate_session");
  });

  it("E2: content_park_pull tells a version skew apart from an outage, like deposit does", async () => {
    const { handlers } = parkFor({ pull: async () => { throw unreachable("protocol_not_supported"); } });
    const res = (await handlers.get("content_park_pull")!(
      { relayMultiaddr: ADDR_A, recipientPubkey: RECIPIENT }, "c1",
    )) as { reason?: string; guidance?: string };
    expect(res.reason).toBe("relay_protocol_unsupported");
    expect(res.guidance).not.toContain("Retry once the relay is up");
  });

  it("E3: content_park_recover maps it too — the handler the order's own evidence names", async () => {
    const { handlers } = parkFor({ pull: async () => { throw unreachable("no_connection"); } });

    const res = (await handlers.get("content_park_recover")!(
      { relayMultiaddr: ADDR_A, recipientPubkey: RECIPIENT }, "c1",
    )) as { ok?: boolean; reason?: string; guidance?: string };

    expect(res.ok).toBe(false);
    expect(res.reason).toBe("relay_unreachable:no_connection");
    // NOT the bare "Recover failed." default, which names no next step at all.
    expect(res.guidance).toContain("cello_initiate_session");
    expect(res.guidance).not.toBe("Recover failed.");
  });

  it("B3: a refusal the relay ITSELF returned is still passed through unchanged", async () => {
    const { handlers, events } = handlersFor(async () => ({ ok: false, reason: "rate_limited" }));

    const res = (await handlers.get("content_park_deposit")!(params, "c1")) as { ok?: boolean; reason?: string };
    expect(res.ok).toBe(false);
    // NOT rewritten into relay_unreachable — the relay answered, and its answer is the cause.
    expect(res.reason).toBe("rate_limited");
    expect(events.filter((e) => e.event === "content.park.deposit.ipc.result")[0]!.context["reason"]).toBe("rate_limited");
  });
});
