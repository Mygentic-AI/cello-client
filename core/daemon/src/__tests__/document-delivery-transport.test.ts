/**
 * DOD-DOC-DELIVERY-2 — the document frame carrier (§16.4). SYNC-P4: the delivery worker, the ack
 * wait and the grace budget are deleted; what remains is session acquisition (reuse before open,
 * opened-then-sealed), the reachability probe, and the suspect-session
 * bypass — all exercised through `sendBytes`, the one send that survives.
 */

import { wireContentHash } from "../wire-content-hash.js";
import { describe, it, expect } from "vitest";
import {
  createDocumentDeliveryTransport,
  type DocumentTransportDeps,
} from "../document-delivery-transport.js";
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
    // DOD-M12B-INDEX-1: the hook now reports whether the leaf actually made it into the chain —
    // a held one has not, and `document.frame.sent` must not read the same for both.
    appendLeaf: () => ({ placed: true, leafIndex: 0 }),
    /**
     * `DOD-M15-SEALWIRE-1` part B2b. The transport now asks ONE place how this session's content is
     * hashed, rather than computing it itself — so the hash and the algorithm it is labelled with
     * cannot disagree. The fixture mirrors production's current answer (`sha256`) rather than
     * inventing one, because a stub that returned something else would be asserting a state the
     * daemon never produces.
     */
    contentHashForSession: (_a: string, _s: string, content: Uint8Array) => ({
      hash: wireContentHash(content),
      alg: "sha256",
    }),
    sendContent: async (_a, sessionId) => {
      sends.push({ sessionId });
      return { ok: true, delivered: true };
    },
    sealSession: async (_a, sessionId) => {
      sealed.push(sessionId);
    },
    logger,
    ...over,
  };
  return { transport: createDocumentDeliveryTransport(deps), events, opened, sends, sealed };
}

const sendInput = (over: Partial<Parameters<ReturnType<typeof createDocumentDeliveryTransport>["sendBytes"]>[0]> = {}) => ({
  peerAgentId: PEER,
  documentId: DOC,
  bytes: new Uint8Array([9]),
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
    const res = await t.transport.sendBytes(sendInput());

    expect(res).toMatchObject({ ok: true, sessionId: "newest", sessionOpened: false });
    // Opening is the expensive half — a negotiation, a dial and a seal — and a backlog for one
    // peer would otherwise pay it per envelope.
    expect(t.opened).toEqual([]);
    expect(t.sends).toEqual([{ sessionId: "newest" }]);
  });

  it("opens one only when there is nothing to reuse, and says it opened", async () => {
    const t = newTransport();
    const res = await t.transport.sendBytes(sendInput());
    expect(res).toMatchObject({ ok: true, sessionId: "opened-session", sessionOpened: true });
    expect(t.opened).toEqual([PEER]);
  });

  it("passes a failed open through with the UPSTREAM reason", async () => {
    const t = newTransport({
      openSession: async () => ({ ok: false, reason: "counterparty_unavailable", guidance: "they did not accept" }),
    });
    const res = await t.transport.sendBytes(sendInput());
    // A dial that was refused should say it was refused; document_delivery_threw is reserved for a
    // genuine programming fault.
    expect(res).toMatchObject({ ok: false, reason: "counterparty_unavailable" });
    expect((res as { detail?: string }).detail).toContain("did not accept");
  });
});


describe("delivery transport — an OPENED session is sealed; a REUSED one is not ours to close", () => {
  it("seals the session it opened", async () => {
    const t = newTransport();
    await t.transport.sendBytes(sendInput());
    // §16.4: the autonomous session still happens because it carries signing, encryption and the
    // seal — the ceremony goes to zero, the seal does not. Walking away leaves a live node the
    // operator never started, and the sealed record the design exists for is never produced.
    expect(t.sealed).toEqual(["opened-session"]);
  });

  it("does NOT seal a session it merely reused", async () => {
    const t = newTransport({ activeSessionsWith: () => ["theirs"] });
    await t.transport.sendBytes(sendInput());
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
/**
 * DOD-MP-SESSION-RETIRE-1, the remaining half — WIRED, not just implemented.
 *
 * The suspects unit beside this one proves the counting. It proves nothing about whether the
 * transport consults it, and a fix that is correct in a module nobody calls is the exact shape of a
 * green suite over a broken daemon. This drives the real transport.
 */
describe("DOD-MP-SESSION-RETIRE-1 — delivery stops REUSING a session that keeps refusing", () => {
  /**
   * THE SHAPE PRODUCTION ACTUALLY PRODUCES.
   *
   * The first version of these tests stubbed `sendContent` to return
   * `{ ok: false, reason: "relay_session_gone" }`, and the real dependency CANNOT return that.
   * `relay_session_gone` is not in `TERMINAL_RELAY_REFUSALS`, so `sendContent` warns, falls through
   * to the direct peer-to-peer send, and on success returns `ok: true, delivered: true` — for a leaf
   * the relay never witnessed. The tests defined a contract the producer does not honour, which is
   * how a green suite sat on top of a fix that could never fire.
   */
  const relayGoneButDelivered = { ok: true as const, delivered: true as const, relayRefusal: "relay_session_gone" };

  it("opens a FRESH session after repeated relay_session_gone, and destroys nothing", async () => {
    const t = newTransport({
      activeSessionsWith: () => ["stuck-session"],
      /**
     * `DOD-M15-SEALWIRE-1` part B2b. The transport now asks ONE place how this session's content is
     * hashed, rather than computing it itself — so the hash and the algorithm it is labelled with
     * cannot disagree. The fixture mirrors production's current answer (`sha256`) rather than
     * inventing one, because a stub that returned something else would be asserting a state the
     * daemon never produces.
     */
    contentHashForSession: (_a: string, _s: string, content: Uint8Array) => ({
      hash: wireContentHash(content),
      alg: "sha256",
    }),
    sendContent: async (_a, sessionId) =>
        sessionId === "stuck-session" ? relayGoneButDelivered : { ok: true as const, delivered: true as const },
    });

    // Two passes. Each one "succeeds" — the content reaches the peer directly — while the session's
    // record is permanently gone. Reading `ok` alone not only missed this, it called noteSuccess and
    // cleared the count, so the session stayed in rotation forever.
    await t.transport.sendBytes(sendInput());
    await t.transport.sendBytes(sendInput());
    expect(t.opened, "one bad answer must not churn a live session").toEqual([]);

    const third = await t.transport.sendBytes(sendInput());
    expect(t.opened, "delivery must open a fresh session instead of reusing a dead record").toEqual([PEER]);
    expect(third.ok).toBe(true);
    // NOTHING WAS DESTROYED. The refused fix retired the session; this leaves it listed and usable
    // by the conversation path, which is what makes it safe when the string merely meant "the relay
    // lost its memory" — it stores sessions in memory and says this after every restart.
    expect(t.sealed).not.toContain("stuck-session");
    // AND IT SAYS SO. A new log event with no assertion is an event nobody can rely on.
    expect(t.events.some((e) => e.event === "document.delivery.session.bypassed")).toBe(true);
  });

  it("a session that RECOVERS keeps being reused — the run must be consecutive", async () => {
    let gone = true;
    const t = newTransport({
      activeSessionsWith: () => ["flaky"],
      /**
     * `DOD-M15-SEALWIRE-1` part B2b. The transport now asks ONE place how this session's content is
     * hashed, rather than computing it itself — so the hash and the algorithm it is labelled with
     * cannot disagree. The fixture mirrors production's current answer (`sha256`) rather than
     * inventing one, because a stub that returned something else would be asserting a state the
     * daemon never produces.
     */
    contentHashForSession: (_a: string, _s: string, content: Uint8Array) => ({
      hash: wireContentHash(content),
      alg: "sha256",
    }),
    sendContent: async () =>
        gone ? relayGoneButDelivered : { ok: true as const, delivered: true as const },
    });
    await t.transport.sendBytes(sendInput());
    gone = false;
    await t.transport.sendBytes(sendInput()); // a witnessed leaf — clears the run
    gone = true;
    await t.transport.sendBytes(sendInput()); // one more, not two in a row
    // A flaky relay is not a dead session. Opening a fresh one here would churn a session that is
    // demonstrably still recording.
    expect(t.opened).toEqual([]);
    expect(t.events.some((e) => e.event === "document.delivery.session.bypassed")).toBe(false);
  });

  it("an OFFLINE peer never condemns the session", async () => {
    const t = newTransport({
      activeSessionsWith: () => ["s"],
      /**
     * `DOD-M15-SEALWIRE-1` part B2b. The transport now asks ONE place how this session's content is
     * hashed, rather than computing it itself — so the hash and the algorithm it is labelled with
     * cannot disagree. The fixture mirrors production's current answer (`sha256`) rather than
     * inventing one, because a stub that returned something else would be asserting a state the
     * daemon never produces.
     */
    contentHashForSession: (_a: string, _s: string, content: Uint8Array) => ({
      hash: wireContentHash(content),
      alg: "sha256",
    }),
    sendContent: async () => ({ ok: false as const, reason: "transport_unavailable", error: "away" }),
    });
    for (let i = 0; i < 4; i++) await t.transport.sendBytes(sendInput());
    // Otherwise every sweep against a sleeping counterparty opens a new session, each sealed moments
    // later — churn dressed up as availability.
    expect(t.opened).toEqual([]);
  });

});
