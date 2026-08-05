/**
 * DOD-DOC-DELIVERY-1 — daemon-autonomous delivery (§16.4).
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import {
  DocumentDelivery,
  backoffFor,
  DELIVERY_BACKOFF_CAP_MS,
  type DocumentDeliveryTransport,
} from "../document-delivery.js";
import { DocumentStore, type DocumentEnvelopeRow } from "../document-store.js";
import type { Logger } from "../types.js";

const AGENT = "owner-agent";
const PEER = "peer-agent";
const DOC = "cc".repeat(32);
const NOW = 1_700_000_000_000;

function recordingLogger(): { logger: Logger; events: Array<{ event: string; fields: Record<string, unknown> }> } {
  const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
  const push = (event: string, fields?: Record<string, unknown>) => {
    events.push({ event, fields: fields ?? {} });
  };
  const logger = { debug: push, info: push, warn: push, error: push, child: () => logger } as unknown as Logger;
  return { logger, events };
}

let seq = 0;
function envelope(sender: string, prev: string | null): DocumentEnvelopeRow {
  seq += 1;
  return {
    envelopeHash: createHash("sha256").update(`env${seq}`).digest("hex"),
    documentId: DOC,
    senderAgentId: sender,
    docPrevHash: prev,
    epochId: 0,
    signature: new Uint8Array(64),
    stateVector: new Uint8Array([0]),
    payload: new Uint8Array([1, 2, 3]),
    kind: "update",
    createdAtMs: NOW + seq,
  };
}

function newFixture(transport: Partial<DocumentDeliveryTransport> = {}) {
  const { logger, events } = recordingLogger();
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  const store = new DocumentStore(db, logger);
  store.createDocument({
    documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
    properties: {}, status: "active", createdAtMs: 1,
  });
  const calls: Array<{ envelopeHash: string; sessionHint?: string }> = [];
  const t: DocumentDeliveryTransport = {
    isPeerReachable: async () => true,
    deliver: async (input) => {
      calls.push({ envelopeHash: input.envelope.envelopeHash, sessionHint: input.sessionHint });
      return { ok: true, sessionId: "session-1" };
    },
    ...transport,
  };
  return {
    store,
    events,
    calls,
    delivery: new DocumentDelivery(store, t, logger),
    peerFor: () => PEER,
  };
}

describe("DocumentDelivery — pending is DERIVED from the log", () => {
  it("delivers an unacknowledged envelope this agent authored, and marks it acked", async () => {
    const f = newFixture();
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);

    const res = await f.delivery.tick(AGENT, f.peerFor, NOW);
    expect(res).toMatchObject({ attempted: 1, delivered: 1 });
    expect(f.store.pendingDeliveries(AGENT, NOW)).toHaveLength(0);
  });

  it("SURVIVES a restart — a fresh worker over the same store still finds the backlog", async () => {
    const f = newFixture({ isPeerReachable: async () => false });
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await f.delivery.tick(AGENT, f.peerFor, NOW);

    // A queue in memory would be gone here, and the operator's update would never be delivered
    // with nothing anywhere reporting a problem. The log is the queue.
    const later = NOW + DELIVERY_BACKOFF_CAP_MS;
    expect(f.store.pendingDeliveries(AGENT, later)).toHaveLength(1);
  });

  it("never re-sends the PEER's own envelopes back at them", async () => {
    const f = newFixture();
    f.store.appendEnvelope(AGENT, envelope(PEER, null));
    // An envelope we RECEIVED is not ours to deliver. Unscoped, a receiver would helpfully bounce
    // every update the sender just sent it straight back.
    expect(await f.delivery.tick(AGENT, f.peerFor, NOW)).toMatchObject({ attempted: 0 });
  });

  it("does not re-deliver an already-acked envelope", async () => {
    const f = newFixture();
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);
    await f.delivery.tick(AGENT, f.peerFor, NOW);
    expect(await f.delivery.tick(AGENT, f.peerFor, NOW + 1)).toMatchObject({ attempted: 0 });
    expect(f.calls).toHaveLength(1);
  });

  it("a second ack for one envelope is recorded as NOT the first", async () => {
    const f = newFixture();
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);
    expect(f.store.markAcked(AGENT, DOC, e.envelopeHash, NOW)).toBe(true);
    // Idempotent: a redelivered ack must not move the clock, or the delivery record would say the
    // peer confirmed at a time it did not.
    expect(f.store.markAcked(AGENT, DOC, e.envelopeHash, NOW + 5_000)).toBe(false);
  });
});

describe("DocumentDelivery — an unreachable peer costs a lookup, not a dial", () => {
  it("defers without dialing when the peer is offline", async () => {
    let dialed = 0;
    const f = newFixture({
      isPeerReachable: async () => false,
      deliver: async () => {
        dialed += 1;
        return { ok: true, sessionId: "s" };
      },
    });
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));

    const res = await f.delivery.tick(AGENT, f.peerFor, NOW);
    expect(res).toMatchObject({ attempted: 0, deferred: 1 });
    // Dialing an offline peer to discover it is offline is the same information at much higher
    // cost — paid per envelope, per tick, for as long as the peer is away.
    expect(dialed).toBe(0);
    expect(f.events.some((e) => e.event === "document.delivery.peer_unreachable")).toBe(true);
  });

  it("one reachability lookup serves the whole backlog for a peer", async () => {
    let lookups = 0;
    const f = newFixture({
      isPeerReachable: async () => {
        lookups += 1;
        return true;
      },
    });
    let prev: string | null = null;
    for (let i = 0; i < 5; i++) {
      const e = envelope(AGENT, prev);
      f.store.appendEnvelope(AGENT, e);
      prev = e.envelopeHash;
    }

    await f.delivery.tick(AGENT, f.peerFor, NOW);
    // Per-envelope lookups multiply directory traffic by the size of the backlog, which is largest
    // exactly when the peer has been away longest.
    expect(lookups).toBe(1);
    expect(f.calls).toHaveLength(5);
  });

  it("a FAILED LOOKUP is not recorded as an offline peer", async () => {
    const f = newFixture({
      isPeerReachable: async () => {
        throw new Error("directory unreachable");
      },
    });
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));

    await f.delivery.tick(AGENT, f.peerFor, NOW);
    // Reporting a directory outage as the collaborator being absent is an error substituted for a
    // different error, and it sends the operator to ask the wrong person.
    expect(f.events.some((e) => e.event === "document.delivery.lookup_failed")).toBe(true);
    expect(f.events.some((e) => e.event === "document.delivery.peer_unreachable")).toBe(false);
  });
});

describe("DocumentDelivery — the backoff is on the ROW, and capped", () => {
  it("grows with attempts and never exceeds the cap", () => {
    expect(backoffFor(0)).toBeLessThan(backoffFor(1));
    expect(backoffFor(1)).toBeLessThan(backoffFor(2));
    for (const n of [0, 1, 5, 50, 5_000]) {
      expect(backoffFor(n)).toBeLessThanOrEqual(DELIVERY_BACKOFF_CAP_MS);
    }
    // Capped, because the peer returning is the event we are waiting for and it can happen at any
    // time — an uncapped curve leaves a returned peer waiting hours for a ready delivery.
    expect(backoffFor(50)).toBe(backoffFor(5_000));
  });

  it("the schedule SURVIVES a restart rather than resetting to full rate", async () => {
    const f = newFixture({ isPeerReachable: async () => false });
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);
    await f.delivery.tick(AGENT, f.peerFor, NOW);
    await f.delivery.tick(AGENT, f.peerFor, NOW + DELIVERY_BACKOFF_CAP_MS);

    const row = f.store.getEnvelopeLog(AGENT, DOC)[0]!;
    expect(row.attempts).toBe(2);
    // A backoff held in memory is not a backoff: a daemon restarting in a reconnect loop would
    // hammer an unreachable peer at full rate forever.
    expect(row.nextAttemptAtMs).toBeGreaterThan(NOW + DELIVERY_BACKOFF_CAP_MS);
  });

  it("an envelope whose next attempt is not yet due is not attempted", async () => {
    const f = newFixture({ isPeerReachable: async () => false });
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await f.delivery.tick(AGENT, f.peerFor, NOW);
    expect(await f.delivery.tick(AGENT, f.peerFor, NOW + 1)).toMatchObject({ attempted: 0, deferred: 0 });
  });
});

describe("DocumentDelivery — one failure does not abandon the rest", () => {
  it("a transport THROW is a failure, never a success, and the pass continues", async () => {
    const f = newFixture({
      deliver: async (input) =>
        input.envelope.logIndex === 0
          ? Promise.reject(new Error("stream reset"))
          : { ok: true, sessionId: "s" },
    });
    let prev: string | null = null;
    for (let i = 0; i < 2; i++) {
      const e = envelope(AGENT, prev);
      f.store.appendEnvelope(AGENT, e);
      prev = e.envelopeHash;
    }

    const res = await f.delivery.tick(AGENT, f.peerFor, NOW);
    expect(res).toMatchObject({ attempted: 2, delivered: 1, failed: 1 });
    // Still pending — a throw must never be recorded as delivered.
    expect(f.store.pendingDeliveries(AGENT, NOW + DELIVERY_BACKOFF_CAP_MS)).toHaveLength(1);
    const failure = f.events.find((e) => e.event === "document.delivery.failed");
    expect(failure!.fields.reason).toBe("document_delivery_threw");
    expect(failure!.fields.detail).toContain("stream reset");
  });

  it("a document with no peer is logged and kept, never silently dropped", async () => {
    const f = newFixture();
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    const res = await f.delivery.tick(AGENT, () => null, NOW);

    expect(res).toMatchObject({ attempted: 0, failed: 1 });
    expect(f.events.some((e) => e.event === "document.delivery.no_peer")).toBe(true);
    // The envelopes are the operator's work. Abandoning them silently is the one outcome an
    // append-only log exists to make impossible.
    expect(f.store.pendingDeliveries(AGENT, NOW)).toHaveLength(1);
  });
});

describe("DocumentDelivery — the session hint (§16.4)", () => {
  it("passes an explicit hint through, and omits it otherwise", async () => {
    const f = newFixture();
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await f.delivery.tick(AGENT, f.peerFor, NOW, { sessionHint: "session-abc" });
    expect(f.calls[0]!.sessionHint).toBe("session-abc");

    const g = newFixture();
    g.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await g.delivery.tick(AGENT, g.peerFor, NOW);
    // Omitted, the daemon chooses — that is the default, not a fallback for a missing value.
    expect(g.calls[0]!.sessionHint).toBeUndefined();
  });
});
