/**
 * DOD-MP-FANOUT-1 — per-(envelope, holder) delivery state.
 *
 * The bilateral columns on the envelope row cannot carry N acknowledgements; this table can. It
 * is DERIVED bookkeeping over the log (the envelope is the truth; a row here says "this holder
 * has not yet confirmed this envelope"), restart-survivable by construction, and per-holder in
 * every dimension: attempts, backoff, ceiling, abandonment.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { DocumentStore, type DocumentEnvelopeRow } from "../document-store.js";
import type { Logger } from "../types.js";

const silent: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} } as Logger;

const AGENT = "a".repeat(64);
const H1 = "b".repeat(64);
const H2 = "c".repeat(64);
const DOC = "d".repeat(64);
const NOW = 1_700_000_000_000;

let seq = 0;
function envelope(): DocumentEnvelopeRow {
  seq += 1;
  return {
    envelopeHash: createHash("sha256").update(`env${seq}`).digest("hex"),
    documentId: DOC,
    senderAgentId: AGENT,
    docPrevHash: null,
    epochId: 0,
    signature: new Uint8Array(64),
    stateVector: new Uint8Array([0]),
    payload: new Uint8Array([1, 2, 3]),
    kind: "update",
    referencesEnvelopeHash: null,
    createdAtMs: NOW,
  };
}

describe("per-holder delivery state", () => {
  let store: DocumentStore;
  beforeEach(() => {
    const db = new DatabaseSync(":memory:");
    store = new DocumentStore(db as never, silent);
    store.createDocument({
      documentId: DOC, ownerAgentId: AGENT, peerAgentId: H1, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
  });

  it("seeding one envelope for two holders yields two independent pending rows", () => {
    const e = envelope();
    store.appendEnvelope(AGENT, e);
    store.seedDeliveries(AGENT, DOC, e.envelopeHash, [H1, H2], NOW);
    const pending = store.pendingHolderDeliveries(AGENT, NOW);
    expect(pending).toHaveLength(2);
    expect(new Set(pending.map((p) => p.holderAgentId))).toEqual(new Set([H1, H2]));
    expect(pending.every((p) => p.envelope.envelopeHash === e.envelopeHash)).toBe(true);
  });

  it("acking ONE holder settles that holder only — the other stays pending", () => {
    const e = envelope();
    store.appendEnvelope(AGENT, e);
    store.seedDeliveries(AGENT, DOC, e.envelopeHash, [H1, H2], NOW);
    expect(store.ackHolderDelivery(AGENT, DOC, e.envelopeHash, H1, NOW)).toBe(true);
    const pending = store.pendingHolderDeliveries(AGENT, NOW);
    expect(pending).toHaveLength(1);
    expect(pending[0]!.holderAgentId).toBe(H2);
    // Settle-once: a redelivered ack reports not-first, changes nothing.
    expect(store.ackHolderDelivery(AGENT, DOC, e.envelopeHash, H1, NOW)).toBe(false);
  });

  it("attempts and backoff are PER HOLDER — recording H1's attempt leaves H2 due now", () => {
    const e = envelope();
    store.appendEnvelope(AGENT, e);
    store.seedDeliveries(AGENT, DOC, e.envelopeHash, [H1, H2], NOW);
    const attempts = store.recordHolderAttempt(AGENT, DOC, e.envelopeHash, H1, NOW + 60_000);
    expect(attempts).toBe(1);
    const due = store.pendingHolderDeliveries(AGENT, NOW + 1);
    expect(due.map((p) => p.holderAgentId)).toEqual([H2]);
    // After H1's backoff elapses it is due again, attempts intact.
    const later = store.pendingHolderDeliveries(AGENT, NOW + 61_000);
    expect(new Set(later.map((p) => p.holderAgentId))).toEqual(new Set([H1, H2]));
    expect(later.find((p) => p.holderAgentId === H1)!.attempts).toBe(1);
  });

  it("abandoning a holder retires THEIR rows only, and reports the count", () => {
    const e1 = envelope();
    const e2 = envelope();
    store.appendEnvelope(AGENT, e1);
    store.appendEnvelope(AGENT, e2);
    store.seedDeliveries(AGENT, DOC, e1.envelopeHash, [H1, H2], NOW);
    store.seedDeliveries(AGENT, DOC, e2.envelopeHash, [H1, H2], NOW);
    const retired = store.abandonHolderDeliveries(AGENT, DOC, H1, NOW);
    expect(retired).toHaveLength(2);
    const pending = store.pendingHolderDeliveries(AGENT, NOW);
    expect(pending.every((p) => p.holderAgentId === H2)).toBe(true);
    expect(pending).toHaveLength(2);
  });

  it("seeding is idempotent — a second seed for the same (envelope, holder) changes nothing", () => {
    const e = envelope();
    store.appendEnvelope(AGENT, e);
    store.seedDeliveries(AGENT, DOC, e.envelopeHash, [H1], NOW);
    store.ackHolderDelivery(AGENT, DOC, e.envelopeHash, H1, NOW);
    store.seedDeliveries(AGENT, DOC, e.envelopeHash, [H1], NOW + 1);
    expect(store.pendingHolderDeliveries(AGENT, NOW + 2)).toHaveLength(0);
  });

  it("the pending window is bounded PER HOLDER — one holder's backlog cannot evict another's", () => {
    // 60 envelopes for H1, 1 for H2, window cap far below 60: H2's row must still appear.
    const hashes: string[] = [];
    for (let i = 0; i < 60; i++) {
      const e = envelope();
      store.appendEnvelope(AGENT, e);
      store.seedDeliveries(AGENT, DOC, e.envelopeHash, [H1], NOW);
      hashes.push(e.envelopeHash);
    }
    const eH2 = envelope();
    store.appendEnvelope(AGENT, eH2);
    store.seedDeliveries(AGENT, DOC, eH2.envelopeHash, [H2], NOW);
    const pending = store.pendingHolderDeliveries(AGENT, NOW, { perHolderLimit: 10 });
    expect(pending.filter((p) => p.holderAgentId === H1)).toHaveLength(10);
    expect(pending.filter((p) => p.holderAgentId === H2)).toHaveLength(1);
  });

  it("holder exhaustion is a per-holder fact the caller can read", () => {
    const e = envelope();
    store.appendEnvelope(AGENT, e);
    store.seedDeliveries(AGENT, DOC, e.envelopeHash, [H1, H2], NOW);
    store.abandonHolderDeliveries(AGENT, DOC, H1, NOW);
    expect(store.holderHasPending(AGENT, DOC, H1)).toBe(false);
    expect(store.holderHasPending(AGENT, DOC, H2)).toBe(true);
  });
});
