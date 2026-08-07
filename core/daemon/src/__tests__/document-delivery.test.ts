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
  DELIVERY_BACKOFF_MS,
  DELIVERY_ACK_TIMEOUT_MS,
  DELIVERY_MAX_UNACKED_SENDS,
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

function newFixture(transport: Partial<DocumentDeliveryTransport> = {}, existingDb?: DatabaseSync) {
  const { logger, events } = recordingLogger();
  const db = existingDb ?? new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  const store = new DocumentStore(db, logger);
  if (!existingDb) {
    store.createDocument({
      documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
  }
  const calls: Array<{ envelopeHash: string; sessionHint?: string }> = [];
  const t: DocumentDeliveryTransport = {
    isPeerReachable: async () => ({ reachable: true, unknownAgent: false }),
    deliver: async (input) => {
      calls.push({ envelopeHash: input.envelope.envelopeHash, sessionHint: input.sessionHint });
      return { ok: true, admitted: true, sessionId: "session-1", sessionOpened: true };
    },
    ...transport,
  };
  return {
    store,
    events,
    calls,
    db,
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

  it("SURVIVES a restart — a SECOND worker over a SECOND store finds the backlog and the count", async () => {
    const f = newFixture({ isPeerReachable: async () => false });
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await f.delivery.tick(AGENT, f.peerFor, NOW);

    // A genuine restart: a new DocumentStore AND a new DocumentDelivery over the same database.
    // The previous version of this test reused both objects, so it asserted "a deferred envelope
    // is due again later" — which an in-memory Map satisfies just as well, and which is the exact
    // thing it was named to disprove.
    const restarted = newFixture({ isPeerReachable: async () => false }, f.db);
    const later = NOW + DELIVERY_BACKOFF_CAP_MS;
    const backlog = restarted.store.pendingDeliveries(AGENT, later);
    expect(backlog).toHaveLength(1);
    // The accumulated attempt count survives too — otherwise the backoff restarts at full rate on
    // every restart, and a daemon in a reconnect loop hammers an unreachable peer forever.
    expect(backlog[0]!.attempts).toBe(1);
    await restarted.delivery.tick(AGENT, restarted.peerFor, later);
    expect(restarted.store.getEnvelopeLog(AGENT, DOC)[0]!.attempts).toBe(2);
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
      isPeerReachable: async () => ({ reachable: false, unknownAgent: false }),
      deliver: async () => {
        dialed += 1;
        return { ok: true, admitted: true, sessionId: "s", sessionOpened: true };
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
        return { reachable: true, unknownAgent: false };
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

  it("the attempt count is persisted on the row, not held in the worker", async () => {
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

  it("schedules the EXACT interval the schedule names, from the pre-increment count", async () => {
    const f = newFixture({ isPeerReachable: async () => false });
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);

    // Nothing asserted the scheduled VALUE before, only that it was "later" — so shifting the
    // schedule by one (backoffFor(attempts + 1)) kept every test green. The delay following the
    // Nth attempt is the Nth entry, counting from the first.
    let at = NOW;
    for (const expected of [DELIVERY_BACKOFF_MS[0], DELIVERY_BACKOFF_MS[1], DELIVERY_BACKOFF_MS[2]]) {
      await f.delivery.tick(AGENT, f.peerFor, at);
      expect(f.store.getEnvelopeLog(AGENT, DOC)[0]!.nextAttemptAtMs).toBe(at + expected!);
      at += expected!;
    }
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
          : { ok: true, admitted: true, sessionId: "s", sessionOpened: false },
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
    // Kept — the envelopes are the operator's work, and abandoning them silently is the one
    // outcome an append-only log exists to make impossible …
    expect(f.store.pendingDeliveries(AGENT, NOW + DELIVERY_BACKOFF_CAP_MS)).toHaveLength(1);
    // … but SCHEDULED. The earlier version asserted it was due immediately, which pinned a hot
    // loop: a missing document row is not transient, so those rows stayed due on every tick
    // forever, and being ordered and bounded, the pending window they filled starved every other
    // document — the operator's work elsewhere silently never leaving the machine.
    expect(f.store.pendingDeliveries(AGENT, NOW + 1)).toHaveLength(0);
  });

  it("a document with no peer does not STARVE a healthy one", async () => {
    const f = newFixture();
    const OTHER = "dd".repeat(32);
    f.store.createDocument({
      documentId: OTHER, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
    for (let i = 0; i < 3; i++) f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    for (let i = 0; i < 3; i++) {
      const e = envelope(AGENT, null);
      f.store.appendEnvelope(AGENT, { ...e, documentId: OTHER });
    }

    // The healthy document makes progress in the SAME pass — a document whose peer cannot be
    // resolved must not hold up one whose peer is right there.
    const first = await f.delivery.tick(AGENT, (d) => (d === DOC ? null : PEER), NOW);
    expect(first).toMatchObject({ delivered: 3, failed: 3 });

    // And on the next pass the broken document is no longer due at all, so it stops consuming the
    // bounded window. Left unscheduled, its rows were due on every tick forever and — being
    // ordered and bounded — could fill that window and starve the healthy document indefinitely.
    const second = await f.delivery.tick(AGENT, (d) => (d === DOC ? null : PEER), NOW + 1);
    expect(second).toMatchObject({ attempted: 0, failed: 0, delivered: 0 });
  });
});

describe("DocumentDelivery — the session hint (§16.4)", () => {
  it("passes an explicit hint through, and omits it otherwise", async () => {
    const f = newFixture();
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await f.delivery.tick(AGENT, f.peerFor, NOW, { sessionHints: new Map([[DOC, "session-abc"]]) });
    expect(f.calls[0]!.sessionHint).toBe("session-abc");

    const g = newFixture();
    g.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await g.delivery.tick(AGENT, g.peerFor, NOW);
    // Omitted, the daemon chooses — that is the default, not a fallback for a missing value.
    expect(g.calls[0]!.sessionHint).toBeUndefined();
  });
});


describe("DocumentDelivery — a rejection is an ACK for delivery purposes (§3.2)", () => {
  it("stops retrying an envelope the peer answered by refusing", async () => {
    const f = newFixture({
      deliver: async () => ({
        ok: true,
        admitted: false,
        sessionId: "s",
        sessionOpened: true,
        rejectionReason: "document_append_only_violation",
      }),
    });
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));

    const res = await f.delivery.tick(AGENT, f.peerFor, NOW);
    expect(res).toMatchObject({ attempted: 1, delivered: 0, rejected: 1 });
    // The peer has DECIDED. Retrying re-triggers their gate and their retry-round counter until
    // the document stalls for reasons the operator cannot see — and supersession is the rejection
    // protocol's job, not the delivery worker's.
    expect(f.store.pendingDeliveries(AGENT, NOW + DELIVERY_BACKOFF_CAP_MS * 10)).toHaveLength(0);
  });

  it("logs a rejection DISTINCTLY from an admission", async () => {
    const f = newFixture({
      deliver: async () => ({
        ok: true, admitted: false, sessionId: "s", sessionOpened: false,
        rejectionReason: "document_update_too_large",
      }),
    });
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await f.delivery.tick(AGENT, f.peerFor, NOW);

    // One string for both would tell the operator their update was accepted when it was refused.
    expect(f.events.some((e) => e.event === "document.delivery.acked")).toBe(false);
    const rejected = f.events.find((e) => e.event === "document.delivery.rejected");
    expect(rejected!.fields.reason).toBe("document_update_too_large");
  });
});

describe("DocumentDelivery — every event carries the correlationId, and the session is logged", () => {
  it("threads one id through lookup, session and ack", async () => {
    const f = newFixture();
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await f.delivery.tick(AGENT, f.peerFor, NOW, { correlationId: "corr-1" });

    const documentEvents = f.events.filter((e) => e.event.startsWith("document.delivery."));
    expect(documentEvents.length).toBeGreaterThan(0);
    // Without a shared id an operator reading a failure cannot tie it to the lookup that preceded
    // it or the session that carried it — across ticks and across restarts.
    for (const e of documentEvents) expect(e.fields.correlationId).toBe("corr-1");
    const session = f.events.find((e) => e.event === "document.delivery.session");
    expect(session!.fields.opened).toBe(true);
  });
});

describe("DocumentDelivery — overlapping ticks do not dial twice", () => {
  it("a second tick during a slow deliver joins the first rather than re-dialing", async () => {
    let dials = 0;
    let release: (() => void) | null = null;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const f = newFixture({
      deliver: async () => {
        dials += 1;
        await gate;
        return { ok: true, admitted: true, sessionId: "s", sessionOpened: true };
      },
    });
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));

    const first = f.delivery.tick(AGENT, f.peerFor, NOW);
    const second = f.delivery.tick(AGENT, f.peerFor, NOW);
    release!();
    await Promise.all([first, second]);

    // A deliver slower than the tick interval is the ordinary case for a distant peer. Without the
    // guard the second tick returns the same rows and dials again: two autonomous sessions and two
    // seals for one envelope, and the loser's ack recorded as if the PEER had redelivered it.
    expect(dials).toBe(1);
  });
});


describe("DocumentDelivery — SENT is neither done nor failed", () => {
  const inFlight = () => ({
    deliver: async () => ({ ok: true as const, admitted: null, sessionId: "s", sessionOpened: true }),
  });

  it("records the envelope as delivered but NOT acked", async () => {
    const f = newFixture(inFlight());
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);

    const res = await f.delivery.tick(AGENT, f.peerFor, NOW);
    expect(res).toMatchObject({ attempted: 1, sent: 1, delivered: 0, failed: 0 });

    const row = f.store.getEnvelopeLog(AGENT, DOC)[0]!;
    // Two different facts: it LEFT, and the peer has not answered. An operator asking why
    // something has not landed needs to tell "sent, awaiting confirmation" from "never sent".
    expect(row.deliveredAtMs).toBe(NOW);
    expect(row.ackedAtMs).toBeNull();
  });

  it("waits the ACK TIMEOUT before sending again — not the failure backoff", async () => {
    const f = newFixture(inFlight());
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await f.delivery.tick(AGENT, f.peerFor, NOW);

    // The EXACT scheduled time. The earlier version asserted only "not due one millisecond later
    // and due at the cap", which any backoff of 2ms satisfies — and the real post-send wait was
    // ONE SECOND, because the pre-dial failure claim was never overwritten. Every resend appends a
    // leaf to the peer's sealed conversation record, so a second is not a cheap mistake.
    expect(f.store.getEnvelopeLog(AGENT, DOC)[0]!.nextAttemptAtMs).toBe(NOW + DELIVERY_ACK_TIMEOUT_MS);
    expect(f.store.pendingDeliveries(AGENT, NOW + DELIVERY_ACK_TIMEOUT_MS - 1)).toHaveLength(0);
    expect(f.store.pendingDeliveries(AGENT, NOW + DELIVERY_ACK_TIMEOUT_MS)).toHaveLength(1);
  });

  it("STALLS the document once an envelope has been sent too many times unacked", async () => {
    const f = newFixture(inFlight());
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));

    let at = NOW;
    for (let i = 0; i < DELIVERY_MAX_UNACKED_SENDS; i++) {
      await f.delivery.tick(AGENT, f.peerFor, at);
      at += DELIVERY_ACK_TIMEOUT_MS;
    }
    // A peer that will never answer must stop being treated as a transient. Unbounded, the envelope
    // is re-sent forever and looks — in the log and in `list` — exactly like one about to land.
    expect(f.store.getDocument(AGENT, DOC)!.status).toBe("stalled");
    expect(f.events.some((e) => e.event === "document.delivery.unacked_limit")).toBe(true);

    // AND IT ACTUALLY STOPS. These two assertions are the whole point, and their absence is why
    // this defect shipped: the test asserted the STATUS and the LOG LINE, both of which the old
    // code set correctly, while the worker kept sending. `pendingDeliveries` filters on
    // `acked_at IS NULL` and reads no status at all, so `stalled` changed what the surface SAID
    // and nothing about what the worker DID. Measured on the operator's live daemon: 74 sends
    // against this cap of 5, with the log insisting publishing had stopped.
    expect(
      f.store.pendingDeliveries(AGENT, at + DELIVERY_ACK_TIMEOUT_MS),
      "the envelope is still queued, so the next tick sends it again — the ceiling stopped nothing",
    ).toHaveLength(0);

    const sendsAtCeiling = f.events.filter((e) => e.event === "document.delivery.sent").length;
    await f.delivery.tick(AGENT, f.peerFor, at + DELIVERY_ACK_TIMEOUT_MS);
    expect(
      f.events.filter((e) => e.event === "document.delivery.sent").length,
      "a tick after the ceiling sent it AGAIN",
    ).toBe(sendsAtCeiling);

    // AND IT IS NOT RECORDED AS ACKED. Giving up is OUR decision; `acked_at` means the peer's
    // daemon answered, and we do not know whether they ever saw this. The first version of the
    // stop-actually-stopping fix reused `markAcked` because it is the column `pendingDeliveries`
    // honours — which would have made `withdraw` tell the operator "your peer holds it, so it
    // cannot be withdrawn" about an envelope that may never have arrived. Same class as any other
    // false claim of confirmation.
    const row = f.store.getEnvelopeLog(AGENT, DOC)[0]!;
    expect(row.ackedAtMs ?? null, "abandoning an envelope claimed the peer had acked it").toBeNull();
  });

  it("an ack arriving later settles it", async () => {
    const f = newFixture(inFlight());
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);
    await f.delivery.tick(AGENT, f.peerFor, NOW);

    expect(f.store.markAcked(AGENT, DOC, e.envelopeHash, NOW + 5_000)).toBe(true);
    expect(f.store.pendingDeliveries(AGENT, NOW + DELIVERY_BACKOFF_CAP_MS)).toHaveLength(0);
    // The delivery time is NOT overwritten by the ack — they are separate moments.
    expect(f.store.getEnvelopeLog(AGENT, DOC)[0]!.deliveredAtMs).toBe(NOW);
  });
});
