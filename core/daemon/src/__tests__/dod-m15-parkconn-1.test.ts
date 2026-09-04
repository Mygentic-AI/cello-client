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

  it("A3: a dial fails and the stream opens anyway → still a non-event", async () => {
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

  it("B3: a refusal the relay ITSELF returned is still passed through unchanged", async () => {
    const { handlers, events } = handlersFor(async () => ({ ok: false, reason: "rate_limited" }));

    const res = (await handlers.get("content_park_deposit")!(params, "c1")) as { ok?: boolean; reason?: string };
    expect(res.ok).toBe(false);
    // NOT rewritten into relay_unreachable — the relay answered, and its answer is the cause.
    expect(res.reason).toBe("rate_limited");
    expect(events.filter((e) => e.event === "content.park.deposit.ipc.result")[0]!.context["reason"]).toBe("rate_limited");
  });
});
