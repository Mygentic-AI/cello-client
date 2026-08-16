/**
 * PROBES for the three findings the 2026-08-16 live fleet run produced. These are DIAGNOSTIC:
 * each one isolates ONE step of the path and asserts what actually happens there, because the
 * fleet log could not attribute its events to an owner and the first reading of it was wrong.
 *
 * The question in every case is the same: when an admin removes a holder, and that holder — not
 * yet knowing — publishes one more edit, who ends up holding it?
 */
import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { Buffer } from "node:buffer";
import { generateKeypair } from "@cello-protocol/crypto";
import { createDocumentLayer, agentPublicKeyFromId } from "../document-layer.js";
import { registerDocumentHandlers } from "../document-handlers.js";
import { DocumentPublish } from "../document-publish.js";
import type { DocumentDeliveryTransport } from "../document-delivery.js";
import type { IpcHandler } from "../ipc-server.js";
import type { Logger } from "../types.js";

const AGENT = "agent";
const CONN = "conn-1";
const NOW = 1_700_000_000_000;

async function newFixture() {
  const keys = generateKeypair();
  const owner = Buffer.from(await keys.getPublicKey()).toString("hex");
  const peerKeys = generateKeypair();
  const peer = Buffer.from(await peerKeys.getPublicKey()).toString("hex");
  const events: string[] = [];
  const nudged: Array<{ documentId: string; seat: string }> = [];
  const record = (event: string) => { events.push(event); };
  const logger = { debug: record, info: record, warn: record, error: record } as unknown as Logger;
  const sent: Array<{ peerAgentId: string; bytes: Uint8Array }> = [];
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");

  const layer = createDocumentLayer({
    db,
    logger,
    sendFrame: async (_o: string, peerAgentId: string, bytes: Uint8Array) => {
      sent.push({ peerAgentId, bytes });
      return { ok: true as const };
    },
    publicKeyFor: agentPublicKeyFromId,
    ownerKeyFor: (agentName) => (agentName === AGENT ? owner : null),
    rollback: () => ({ ok: true }),
    sign: async (_o, tbs) => keys.sign(tbs),
  });

  const transport = {
    isPeerReachable: async () => ({ reachable: true, unknownAgent: false }),
    sendBytes: async (input: { peerAgentId: string; bytes: Uint8Array }) => {
      sent.push({ peerAgentId: input.peerAgentId, bytes: input.bytes });
      return { ok: true as const, sessionId: "session-1", sessionOpened: true };
    },
    deliver: async () => ({ ok: true as const, sessionId: "s", sessionOpened: false, admitted: null }),
  } satisfies DocumentDeliveryTransport;

  const handlers = new Map<string, IpcHandler>();
  registerDocumentHandlers({
    handlers,
    logger,
    layer,
    publish: new DocumentPublish({
      governanceFrontierFor: (o, d) => layer.governanceFrontierFor(o, d),
      holdersFor: (o, d) => layer.holdersFor(o, d),
      store: layer.store,
      engine: layer.engine,
      logger,
      sign: async (_o, tbs) => keys.sign(tbs),
      senderIdFor: (o) => o,
      canPublish: (o, d) => layer.lifecycle.canPublish(o, d),
      nudgeSeats: (_o, documentId, seats) => {
        for (const seat of seats) nudged.push({ documentId, seat });
      },
    }),
    transportFor: () => transport,
    resolveAgent: (_c, explicit) => explicit ?? AGENT,
    ownerKeyFor: (agentName) => (agentName === AGENT ? owner : null),
    sign: async (_a, tbs) => keys.sign(tbs),
    now: () => NOW,
  });

  const call = (verb: string, params: Record<string, unknown> = {}) =>
    handlers.get(verb)!(params, CONN) as Promise<Record<string, unknown>>;

  return { owner, peer, layer, sent, events, nudged, call };
}
type Fx = Awaited<ReturnType<typeof newFixture>>;

/**
 * Deliver every frame addressed to `to` and CONSUME it — a real wire delivers each frame once.
 * (The suite's shared `routeAll` re-delivers the whole backlog every call, which is fine for a
 * bounded hand-rolled sequence and an infinite loop for a drive-until-quiet helper.)
 */
function drain(from: Fx, to: Fx): number {
  const mine = from.sent.filter((s) => s.peerAgentId === to.owner);
  const rest = from.sent.filter((s) => s.peerAgentId !== to.owner);
  from.sent.length = 0;
  from.sent.push(...rest);
  for (const send of mine) {
    to.layer.onDocumentFrame(AGENT, "session-1", send.bytes, from.owner);
  }
  return mine.length;
}
/** Re-delivering backlog, for the join bootstrap which is written against repeat delivery. */
function routeAll(from: Fx, to: Fx) {
  for (const send of from.sent) {
    if (send.peerAgentId === to.owner) {
      to.layer.onDocumentFrame(AGENT, "session-1", send.bytes, from.owner);
    }
  }
}
const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 30));

/**
 * Run a REAL exchange between two fixtures: `from` initiates (step 1), then frames bounce until
 * neither side sends anything new. The fixture stubs `nudgeSeats`, so a publish alone puts NO
 * bytes on the wire — every probe must drive the exchange itself or it measures nothing.
 */
async function exchange(from: Fx, to: Fx, documentId: string, rounds = 8): Promise<void> {
  await from.layer.initiateReconcile(from.owner, to.owner, [documentId]);
  for (let i = 0; i < rounds; i++) {
    await settle();
    const a = drain(from, to);
    await settle();
    const b = drain(to, from);
    await settle();
    if (a === 0 && b === 0) return; // silence terminates the exchange (R15)
  }
}

/** Bounce the exchange until the invitee holds the document. */
async function seatViaExchange(inviter: Fx, invitee: Fx, documentId: string): Promise<void> {
  for (let i = 0; i < 8 && invitee.layer.store.getDocument(invitee.owner, documentId) === null; i++) {
    routeAll(inviter, invitee);
    await settle();
    routeAll(invitee, inviter);
    await settle();
  }
}

const textOf = (f: Fx, documentId: string): string =>
  f.layer.live.get(f.owner, documentId).getText("content").toString();

/** A and B seated on one document, B a plain holder, A the sole admin. */
async function twoSeated(): Promise<{ fA: Fx; fB: Fx; documentId: string }> {
  const fA = await newFixture();
  const fB = await newFixture();
  const proposed = await fA.call("cello_doc_propose", {
    peer_pubkey: fB.owner,
    starting_content: "base. ",
    admins: [fA.owner],
  });
  const documentId = proposed.documentId as string;
  await seatViaExchange(fA, fB, documentId);
  await fB.call("cello_doc_accept", { document_id: documentId });
  routeAll(fB, fA);
  await settle();
  return { fA, fB, documentId };
}

describe("PROBE 1 — the remover's door, with only two parties", () => {
  it("says what A does with an edit B authored BEFORE B could know it was removed", async () => {
    const { fA, fB, documentId } = await twoSeated();
    expect(textOf(fB, documentId)).toBe("base. ");

    // A removes B. Nothing is routed to B, so B's world still seats B — which is exactly the
    // live case: the removal had not reached them when they wrote.
    const removed = await fA.call("cello_doc_remove", {
      document_id: documentId, holder_pubkey: fB.owner,
    });
    expect(removed.ok).toBe(true);
    fA.sent.length = 0; // drop the removal notice; B stays ignorant on purpose

    // B writes. Its own gate must ALLOW this — at the frontier B names, B is seated.
    const wrote = await fB.call("cello_doc_write", {
      document_id: documentId, content: "base. B's last edit, authored in good faith. ",
    });
    expect(wrote, "B's own daemon refused an edit it had no reason to refuse").toMatchObject({
      ok: true, published: true,
    });

    // SPLIT, because the two directions are NOT the same path.
    // (a) B initiates — the only thing a removed holder can do on its own.
    await exchange(fB, fA, documentId);
    const afterBInitiated = textOf(fA, documentId).includes("B's last edit");
    // (b) A initiates — which A only does for parties its own fold still seats.
    await exchange(fA, fB, documentId);
    const afterAInitiated = textOf(fA, documentId).includes("B's last edit");
    console.log("PROBE1 A has it after B initiated:", afterBInitiated,
      "| after A initiated:", afterAInitiated);

    // MEASURED, and it disproves the "two parties, so nobody can forward it" reading: B's own
    // initiative is ENOUGH. The remover applies what a frame CARRIES before it rules on whether
    // to answer the sender (`APPLY FIRST` in handleReconcile), so a terminal refusal stops A
    // SERVING B — it does not stop B's good-faith work reaching A.
    expect(afterBInitiated, "B's own exchange did not carry its last edit to the remover").toBe(true);
    expect(afterAInitiated).toBe(true);
    // And the refusal really did fire, so this is not "the gate never ran".
    expect(fA.events.filter((e) => e === "document.reconcile.refused").length).toBeGreaterThan(0);
  });
});

describe("PROBE 2 — the third-party forward, which is what saved the live run", () => {
  it("says whether C can carry B's pre-removal edit to A after A refused B directly", async () => {
    const { fA, fB, documentId } = await twoSeated();
    const fC = await newFixture();
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    await seatViaExchange(fA, fC, documentId);
    await fC.call("cello_doc_accept", { document_id: documentId });
    routeAll(fC, fA);
    await settle();
    routeAll(fA, fB);
    await settle();
    routeAll(fB, fA);
    await settle();

    await fA.call("cello_doc_remove", { document_id: documentId, holder_pubkey: fB.owner });
    fA.sent.length = 0; // B stays ignorant; C is NOT told either, so C still seats B
    await fB.call("cello_doc_write", {
      document_id: documentId, content: "base. B's last edit, authored in good faith. ",
    });

    // B's edit reaches C (who does not hold the removal) and A (who does).
    await exchange(fB, fC, documentId);
    await exchange(fB, fA, documentId);
    const cHasIt = textOf(fC, documentId).includes("B's last edit");
    const aBefore = textOf(fA, documentId).includes("B's last edit");
    // A already has it directly — the third-party forward was never the load-bearing path.
    expect(cHasIt).toBe(true);
    expect(aBefore).toBe(true);

    // Now C exchanges with A — the forward path.
    fC.sent.length = 0;
    await exchange(fC, fA, documentId);
    await exchange(fA, fC, documentId);
    const aAfter = textOf(fA, documentId).includes("B's last edit");
    expect(aAfter).toBe(true);
  });
});

describe("PROBE 3 — does taking content from the exchange nudge the other seats?", () => {
  it("says whether a holder that ADMITS an envelope from the exchange passes it on without waiting for a sweep", async () => {
    const { fA, fB, documentId } = await twoSeated();
    const fC = await newFixture();
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    await seatViaExchange(fA, fC, documentId);
    await fC.call("cello_doc_accept", { document_id: documentId });
    routeAll(fC, fA);
    await settle();
    routeAll(fA, fB);
    await settle();

    // B publishes ordinarily. A takes it through the exchange. Does A then nudge C?
    await fB.call("cello_doc_write", {
      document_id: documentId, content: "base. B writes once. ",
    });
    fA.nudged.length = 0;
    const aSentBefore = fA.sent.filter((x) => x.peerAgentId === fC.owner).length;
    await exchange(fB, fA, documentId);
    const aSentToC = fA.sent.filter((x) => x.peerAgentId === fC.owner).length - aSentBefore;
    const admitted = textOf(fA, documentId).includes("B writes once");
    expect(admitted, "A did not take B's edit through the exchange").toBe(true);
    // THE CONFIRMED GAP (DOD-SYNC-EXCHANGE-NO-FANOUT-1): A now holds content C does not, and
    // does NOTHING about it — no nudge, not one frame. C waits for a sweep. Publishing nudges
    // the seats; TAKING content from the exchange does not, and the difference is invisible
    // because the sweep eventually covers it. **When that is fixed, this test flips.**
    expect(fA.nudged, "the gap is closed — flip this assertion").toEqual([]);
    expect(aSentToC, "A passed the new content on; the gap is closed — flip this assertion").toBe(0);
  });
});

describe("PROBE 4 — the difference between the probe and the fleet: WHEN B learns", () => {
  it("says whether B's last edit still reaches A if B learns of its removal before the exchange completes", async () => {
    const { fA, fB, documentId } = await twoSeated();
    await fA.call("cello_doc_remove", { document_id: documentId, holder_pubkey: fB.owner });
    const removalFrames = fA.sent.filter((x) => x.peerAgentId === fB.owner);
    fA.sent.length = 0;

    // B writes while still ignorant — the good-faith edit.
    const wrote = await fB.call("cello_doc_write", {
      document_id: documentId, content: "base. B's last edit, authored in good faith. ",
    });
    expect(wrote).toMatchObject({ ok: true, published: true });

    // NOW B learns — which on the fleet happened about two seconds after the publish, before
    // any exchange had a chance to carry the edit across.
    for (const f of removalFrames) {
      fB.layer.onDocumentFrame(AGENT, "session-1", f.bytes, fA.owner);
    }
    await settle();
    const bKnows = fB.layer.standingOf(fB.owner, documentId, fB.owner);

    // Give both sides every chance: B tries, A tries.
    await exchange(fB, fA, documentId);
    await exchange(fA, fB, documentId);
    const aHasIt = textOf(fA, documentId).includes("B's last edit");
    expect(bKnows).toBe("removed");
    // Still arrives. Learning first does not strand the edit either — so the fleet's five-minute
    // wait was never a loss, only a wait for something to START an exchange.
    expect(aHasIt, "B's last edit was stranded once B knew it was removed").toBe(true);
  });
});
