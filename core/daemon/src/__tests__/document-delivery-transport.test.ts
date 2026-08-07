/**
 * DOD-DOC-DELIVERY-2 — the transport behind the delivery worker's seam (§16.4).
 */

import { describe, it, expect, vi } from "vitest";
import {
  createDocumentDeliveryTransport,
  DELIVERY_ACK_GRACE_MS,
  type DocumentTransportDeps,
} from "../document-delivery-transport.js";
import type { DocumentEnvelopeRow } from "../document-store.js";
import type { Logger } from "../types.js";

const AGENT = "agent-a";
const PEER = "peer-b";
const DOC = "cc".repeat(32);

function recordingLogger(): { logger: Logger; events: Array<{ event: string; fields: Record<string, unknown> }> } {
  const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
  const push = (event: string, fields?: Record<string, unknown>) => {
    events.push({ event, fields: fields ?? {} });
  };
  const logger = { debug: push, info: push, warn: push, error: push, child: () => logger } as unknown as Logger;
  return { logger, events };
}

const envelope = {
  envelopeHash: "11".repeat(32),
  documentId: DOC,
  senderAgentId: AGENT,
  docPrevHash: null,
  epochId: 0,
  signature: new Uint8Array(64),
  stateVector: new Uint8Array([0]),
  payload: new Uint8Array([1, 2, 3]),
  kind: "update" as const,
  createdAtMs: 1,
};

function newTransport(over: Partial<DocumentTransportDeps> = {}) {
  const { logger, events } = recordingLogger();
  const opened: string[] = [];
  const sends: Array<{ sessionId: string }> = [];
  const sealed: string[] = [];
  const deps: DocumentTransportDeps = {
    agentName: AGENT,
    lookupPeer: async () => ({ kind: "result", state: "online", owningNodeIds: ["n1"] }),
    activeSessionsWith: () => [],
    openSession: async (_a, p) => {
      opened.push(p);
      return { ok: true, sessionId: "opened-session" };
    },
    // The sender's own `0x04` leaf. Required, not optional: `cello_send` takes its leaf position
    // after every successful send, and a document sender that skips it leaves its own tree behind
    // by one per frame — which starves its INBOUND, because the receive path holds anything whose
    // canonical sequence is ahead of its own tree size.
    appendLeaf: () => {},
    sendContent: async (_a, sessionId) => {
      sends.push({ sessionId });
      return { ok: true, delivered: true };
    },
    sealSession: async (_a, sessionId) => {
      sealed.push(sessionId);
    },
    encodeEnvelope: () => ({ bytes: new Uint8Array([9]), hash: new Uint8Array(32) }),
    // Default: the peer answers immediately. Overridden per test to model a slow or silent one.
    awaitAck: async () => true,
    drainHeld: async () => {},
    logger,
    ...over,
  };
  return { transport: createDocumentDeliveryTransport(deps), events, opened, sends, sealed };
}

const deliverInput = (over: Partial<Parameters<ReturnType<typeof createDocumentDeliveryTransport>["deliver"]>[0]> = {}) => ({
  peerAgentId: PEER,
  documentId: DOC,
  envelope: envelope as DocumentEnvelopeRow,
  correlationId: "corr-1",
  // The pass budget the worker hands down. Generous by default; individual tests shrink it.
  ackGraceMs: 10_000,
  ...over,
});

describe("delivery transport — reachability comes from discovery, not from a dial", () => {
  it("reports an online peer as reachable", async () => {
    const t = newTransport();
    expect(await t.transport.isPeerReachable(PEER, "c")).toMatchObject({ reachable: true });
  });

  it("reports an offline peer as unreachable", async () => {
    const t = newTransport({
      lookupPeer: async () => ({ kind: "result", state: "offline", owningNodeIds: [] }),
    });
    expect(await t.transport.isPeerReachable(PEER, "c")).toMatchObject({ reachable: false });
  });

  it("names an unknown agent DISTINCTLY from an offline one", async () => {
    const t = newTransport({
      lookupPeer: async () => ({ kind: "result", state: "unknown_agent", owningNodeIds: [] }),
    });
    // RETURNED, not logged here: the worker announces it against the document it belongs to, so
    // an operator can join "this address does not resolve" to the document it concerns.
    expect(await t.transport.isPeerReachable(PEER, "c")).toEqual({
      reachable: false,
      unknownAgent: true,
    });
  });

  it("THROWS when the lookup itself failed, rather than calling the peer offline", async () => {
    const t = newTransport({ lookupPeer: async () => ({ kind: "timeout" }) });
    // The worker turns this into lookup_failed and keeps it out of the offline count. Returning
    // false would report a directory or transport fault as the peer being absent.
    await expect(t.transport.isPeerReachable(PEER, "c")).rejects.toThrow(/document_discovery_unavailable/);
  });
});

describe("delivery transport — REUSE before open (§16.4)", () => {
  it("reuses the most recent active session and opens nothing", async () => {
    const t = newTransport({ activeSessionsWith: () => ["older", "newest"] });
    const res = await t.transport.deliver(deliverInput());

    expect(res).toMatchObject({ ok: true, sessionId: "newest", sessionOpened: false });
    // Opening is the expensive half — a negotiation, a dial and a seal — and a backlog for one
    // peer would otherwise pay it per envelope.
    expect(t.opened).toEqual([]);
    expect(t.sends).toEqual([{ sessionId: "newest" }]);
  });

  it("opens one only when there is nothing to reuse, and says it opened", async () => {
    const t = newTransport();
    const res = await t.transport.deliver(deliverInput());
    expect(res).toMatchObject({ ok: true, sessionId: "opened-session", sessionOpened: true });
    expect(t.opened).toEqual([PEER]);
  });

  it("passes a failed open through with the UPSTREAM reason", async () => {
    const t = newTransport({
      openSession: async () => ({ ok: false, reason: "counterparty_unavailable", guidance: "they did not accept" }),
    });
    const res = await t.transport.deliver(deliverInput());
    // A dial that was refused should say it was refused; document_delivery_threw is reserved for a
    // genuine programming fault.
    expect(res).toMatchObject({ ok: false, reason: "counterparty_unavailable" });
    expect((res as { detail?: string }).detail).toContain("did not accept");
  });
});

describe("delivery transport — the session hint is honoured or REFUSED, never substituted", () => {
  it("uses an explicit hint that names an active session", async () => {
    const t = newTransport({ activeSessionsWith: () => ["a", "b"] });
    const res = await t.transport.deliver(deliverInput({ sessionHint: "a" }));
    expect(res).toMatchObject({ ok: true, sessionId: "a" });
  });

  it("REFUSES a hint that is not an active session with this peer", async () => {
    const t = newTransport({ activeSessionsWith: () => ["a"] });
    const res = await t.transport.deliver(deliverInput({ sessionHint: "not-a-session" }));

    // The only reason to pass a hint is to control which sealed record the change lands in.
    // Quietly substituting the daemon's own pick defeats exactly that, silently.
    expect(res).toMatchObject({ ok: false, reason: "document_session_hint_invalid" });
    expect(t.sends).toEqual([]);
  });
});

describe("delivery transport — a send is SENT, not acked", () => {
  it("returns admitted: null for a delivered envelope", async () => {
    const t = newTransport({ activeSessionsWith: () => ["s"] });
    const res = await t.transport.deliver(deliverInput());
    // `true` would mark it acknowledged while the peer may never have applied it; `false` would
    // count a send that worked as a failure and re-send content already in flight.
    expect(res).toMatchObject({ ok: true, admitted: null });
  });

  it("returns admitted: null for content PARKED for an offline peer, too", async () => {
    const t = newTransport({
      activeSessionsWith: () => ["s"],
      sendContent: async () => ({ ok: true, delivered: false, parked: true }),
    });
    const res = await t.transport.deliver(deliverInput());
    expect(res).toMatchObject({ ok: true, admitted: null });
    expect(t.events.find((e) => e.event === "document.delivery.sent")!.fields.parked).toBe(true);
  });

  it("a failed send is a FAILURE, carrying the transport's own reason", async () => {
    const t = newTransport({
      activeSessionsWith: () => ["s"],
      sendContent: async () => ({ ok: false, reason: "session_node_unavailable", error: "no active session node" }),
    });
    const res = await t.transport.deliver(deliverInput());
    expect(res).toMatchObject({ ok: false, reason: "session_node_unavailable" });
    expect((res as { detail?: string }).detail).toContain("no active session node");
  });
});


describe("delivery transport — an OPENED session is sealed; a REUSED one is not ours to close", () => {
  it("seals the session it opened", async () => {
    const t = newTransport();
    await t.transport.deliver(deliverInput());
    // §16.4: the autonomous session still happens because it carries signing, encryption and the
    // seal — the ceremony goes to zero, the seal does not. Walking away leaves a live node the
    // operator never started, and the sealed record the design exists for is never produced.
    expect(t.sealed).toEqual(["opened-session"]);
  });

  it("does NOT seal a session it merely reused", async () => {
    const t = newTransport({ activeSessionsWith: () => ["theirs"] });
    await t.transport.deliver(deliverInput());
    // Its owner decides when that conversation ends.
    expect(t.sealed).toEqual([]);
  });
});

/**
 * DOD-DOC-SEAL-ACK-1 — a session we opened stays up until the answer is in.
 *
 * The seal DESTROYS the session, and the teardown drops content still held for ordering. So an ack
 * that is sent correctly and received correctly can still be deleted, and the sender re-sends until
 * the unacked ceiling retires the envelope. Measured live: `session.content.held` on the ack, then
 * `session.node.destroyed reason=sealed` three seconds later, then 90 re-sends against a cap of 5.
 */
describe("a session the worker OPENED is not sealed until the peer has answered", () => {
  it("waits for the ack BEFORE sealing", async () => {
    const order: string[] = [];
    let releaseAck: (() => void) | undefined;
    const f = newTransport({
      awaitAck: () =>
        new Promise<boolean>((resolve) => {
          order.push("await");
          releaseAck = () => resolve(true);
        }),
      sealSession: async () => {
        order.push("seal");
      },
    });

    const inFlight = f.transport.deliver(deliverInput());
    await vi.waitFor(() => expect(order).toEqual(["await"]));
    // The seal has NOT happened yet. That is the whole property: sealing here is what deletes the
    // held ack, so the wait has to come first rather than alongside.
    expect(order).toEqual(["await"]);
    releaseAck!();
    await inFlight;
    expect(order).toEqual(["await", "seal"]);
  });

  it("SEALS ANYWAY when the peer never answers, and says so", async () => {
    // The grace period is a bound, not a promise. A peer that never answers must not leave an
    // autonomous session running — that is the live node the seal exists to prevent.
    const f = newTransport({ awaitAck: async () => false });
    await f.transport.deliver(deliverInput());
    expect(f.sealed).toEqual(["opened-session"]);
    // Said out loud, because a seal that discards a held ack is otherwise invisible and this is the
    // only moment anything knows it is about to happen.
    expect(f.events.some((e) => e.event === "document.delivery.ack_grace_expired")).toBe(true);
  });

  it("does NOT wait on a session it REUSED — that one is not ours to close", async () => {
    let waited = 0;
    const f = newTransport({
      activeSessionsWith: () => ["existing-session"],
      awaitAck: async () => {
        waited += 1;
        return true;
      },
    });
    await f.transport.deliver(deliverInput());
    // A reused session stays alive because its owner keeps it, so the ack already has all the time
    // it needs. Waiting here would hold up every delivery on a live conversation for nothing —
    // and this asymmetry is exactly why the spine enforcers never saw the defect.
    expect(waited).toBe(0);
    expect(f.sealed).toEqual([]);
  });
});

describe("the ack grace is a BUDGET the caller controls, not a fixed cost per envelope", () => {
  it("passes the ENVELOPE HASH and the granted grace to the waiter", async () => {
    // Pins the ARGUMENTS, not just that a wait happened. Both have been wrong in this feature
    // before — the owner key vs the agent name, the sender id vs the owner key — and a stubbed
    // seam that asserts nothing about what flows through it cannot catch either.
    const calls: Array<[string, number]> = [];
    const t = newTransport({
      awaitAck: async (hash, ms) => {
        calls.push([hash, ms]);
        return true;
      },
    });
    await t.transport.deliver(deliverInput({ ackGraceMs: 4_000 }));
    expect(calls).toEqual([[envelope.envelopeHash, 4_000]]);
  });

  it("waits for the SMALLER of the standard grace and what the pass has left", async () => {
    const calls: number[] = [];
    const t = newTransport({ awaitAck: async (_h, ms) => { calls.push(ms); return true; } });
    await t.transport.deliver(deliverInput({ ackGraceMs: 500_000 }));
    expect(calls).toEqual([DELIVERY_ACK_GRACE_MS]);
  });

  it("does NOT wait once the pass budget is spent — and STILL seals", async () => {
    // The sweep must not stall behind whoever exhausted the budget. But the seal is unconditional:
    // an autonomous session left running is the thing the seal exists to prevent, and trading the
    // wait for that would be a worse defect than the one being fixed.
    let waited = 0;
    const t = newTransport({ awaitAck: async () => { waited += 1; return true; } });
    await t.transport.deliver(deliverInput({ ackGraceMs: 0 }));
    expect(waited).toBe(0);
    expect(t.sealed).toEqual(["opened-session"]);
  });

  it("does NOT wait for PARKED content — an offline peer cannot answer within any grace", async () => {
    let waited = 0;
    const t = newTransport({
      sendContent: async () => ({ ok: true, delivered: false, parked: true }),
      awaitAck: async () => { waited += 1; return true; },
    });
    await t.transport.deliver(deliverInput());
    // Waiting here spent the budget on a certainty and fired ack_grace_expired on a designed,
    // benign state — a warning that cried wolf on the normal offline-peer case.
    expect(waited).toBe(0);
    expect(t.events.some((e) => e.event === "document.delivery.ack_grace_expired")).toBe(false);
    expect(t.sealed).toEqual(["opened-session"]);
  });
});

describe("the grace DRAINS held content before waiting — otherwise it cannot help at all", () => {
  it("drains BEFORE the wait, not after", async () => {
    // The ordering is the property. An ack whose canonical sequence is ahead of our tree is HELD,
    // and held content is never routed to the document layer — it waits for the missing sequence to
    // arrive, not for time to pass. Waiting first and draining after would let the full grace
    // expire on an ack already sitting in the buffer, which is the exact failure the grace was
    // added to fix, made slower.
    const order: string[] = [];
    const t = newTransport({
      drainHeld: async () => { order.push("drain"); },
      awaitAck: async () => { order.push("await"); return true; },
    });
    await t.transport.deliver(deliverInput());
    expect(order).toEqual(["drain", "await"]);
  });

  it("does not drain when it is not going to wait", async () => {
    // No wait, no point unsticking anything for it — and a relay round trip per parked envelope is
    // exactly the cost the pass budget exists to bound.
    const t = newTransport({
      sendContent: async () => ({ ok: true, delivered: false, parked: true }),
      drainHeld: async () => { throw new Error("drained on a parked send"); },
    });
    await expect(t.transport.deliver(deliverInput())).resolves.toMatchObject({ ok: true });
  });

  it("a drain that THROWS does not fail the delivery — the content already left", async () => {
    // Caught by the test disagreeing with its own name: it asserted `rejects.toThrow()` and passed,
    // which meant a relay hiccup during the drain surfaced as `document_delivery_threw` and
    // re-sent content the peer already held. The name was right and the code was wrong.
    const t = newTransport({ drainHeld: async () => { throw new Error("relay down"); } });
    await expect(t.transport.deliver(deliverInput())).resolves.toMatchObject({ ok: true });
    expect(t.events.some((e) => e.event === "document.delivery.drain_threw")).toBe(true);
    // And the session is still sealed — a failed drain must not leave an autonomous session up.
    expect(t.sealed).toEqual(["opened-session"]);
  });
});
