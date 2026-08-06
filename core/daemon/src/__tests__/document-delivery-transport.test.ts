/**
 * DOD-DOC-DELIVERY-2 — the transport behind the delivery worker's seam (§16.4).
 */

import { describe, it, expect } from "vitest";
import {
  createDocumentDeliveryTransport,
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
