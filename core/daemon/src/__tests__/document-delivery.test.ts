/**
 * DOD-DOC-DELIVERY-1 — daemon-autonomous delivery (§16.4).
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import {
  documentAmendmentHash,
  encodeDocumentAmendment,
} from "@cello-protocol/protocol-types";
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
    holdersFor: () => [PEER],
  };
}

describe("FANOUT-1 — deferrals never spend the ceiling: attempts schedule, sends gate", () => {
  it("an offline weekend does not abandon the first real send after the holder returns", async () => {
    // The Entry-15 defect, pinned: re-conflate the counters (drive the ceiling from attempts)
    // and this goes red — after 5+ quiet deferrals the first live send would abandon the row.
    const wire = { online: false };
    const f = newFixture({
      isPeerReachable: async () => ({ reachable: wire.online, unknownAgent: false }),
      deliver: async () => ({ ok: true as const, admitted: null, parked: false, sessionId: "s", sessionOpened: true }),
    });
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    let at = NOW;
    for (let i = 0; i < DELIVERY_MAX_UNACKED_SENDS + 2; i++) {
      await f.delivery.tick(AGENT, f.holdersFor, at);
      at += DELIVERY_BACKOFF_CAP_MS;
    }
    // Seven quiet deferrals; nothing dialed, nothing abandoned.
    expect(f.calls).toHaveLength(0);
    wire.online = true;
    const res = await f.delivery.tick(AGENT, f.holdersFor, at);
    expect(res).toMatchObject({ sent: 1 });
    // The row SURVIVES — one real send against a ceiling of five.
    expect(f.store.holderHasPending(AGENT, DOC, PEER)).toBe(true);
    expect(f.events.some((e) => e.event === "document.delivery.unacked_limit")).toBe(false);
  });
});

describe("DOD-MP-REMOVE-1 — the worker STOPS DELIVERING to a removed peer", () => {
  it("retires pending envelopes to a removed target without dialing — abandoned, not redialed forever", async () => {
    const f = newFixture();
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    // The peer is REMOVED per the recorded chain (a decodable amendment row — the walk decodes
    // every stored row).
    const body = {
      document_id: DOC, epoch_id: 1, prev_amendment_hash: null,
      kind: "remove_holder", subject_agent_id: PEER,
      property_change: null, state_hash: null, authored_at_ms: 1,
    } as const;
    const hash = documentAmendmentHash(body);
    const bytes = encodeDocumentAmendment({
      body,
      collection: {
        document_id: DOC, subject_kind: "document_amendment", subject_hash: hash,
        required_signers: ["a".repeat(64)],
        signatures: [{ signer_agent_id: "a".repeat(64), signature: new Uint8Array(64) }],
      },
    });
    f.db.prepare(
      `INSERT INTO document_amendments
         (owner_agent_id, document_id, epoch_id, amendment_hash, received_bytes, recorded_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(AGENT, DOC, 1, Buffer.from(hash).toString("hex"), Buffer.from(bytes), 1);

    const res = await f.delivery.tick(AGENT, f.holdersFor, NOW);
    // No dial, no retry: the envelope is RETIRED (our decision, announced), pending drains.
    expect(f.calls).toHaveLength(0);
    expect(res.attempted).toBe(0);
    expect(f.store.pendingDeliveries(AGENT, NOW)).toHaveLength(0);
    expect(f.events.some((e) => e.event === "document.delivery.peer_removed")).toBe(true);
  });
});

describe("DOD-MP-FANOUT-1 — one unreachable holder never blocks the others", () => {
  it("delivers to the reachable holder in the SAME pass the unreachable one defers", async () => {
    const H2 = "ee".repeat(32);
    const f = newFixture({
      isPeerReachable: async (peerAgentId) => ({
        reachable: peerAgentId === H2,
        unknownAgent: false,
      }),
    });
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);
    f.store.seedDeliveries(AGENT, DOC, e.envelopeHash, [PEER, H2], NOW);

    const res = await f.delivery.tick(AGENT, () => [PEER, H2], NOW);
    // The availability clause, directly: H2 got the envelope while PEER deferred — neither
    // waited on the other, and the settled half stays settled.
    expect(res).toMatchObject({ delivered: 1, deferred: 1 });
    expect(f.calls).toHaveLength(1);
    expect(f.store.holderHasPending(AGENT, DOC, H2)).toBe(false);
    expect(f.store.holderHasPending(AGENT, DOC, PEER)).toBe(true);
    // And the envelope-level record does NOT claim all-confirmed while one holder is owed.
    expect(f.store.getEnvelopeLog(AGENT, DOC)[0]!.ackedAtMs).toBeNull();
  });
});

describe("DocumentDelivery — pending is DERIVED from the log", () => {
  it("delivers an unacknowledged envelope this agent authored, and marks it acked", async () => {
    const f = newFixture();
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);

    const res = await f.delivery.tick(AGENT, f.holdersFor, NOW);
    expect(res).toMatchObject({ attempted: 1, delivered: 1 });
    expect(f.store.pendingDeliveries(AGENT, NOW)).toHaveLength(0);
  });

  it("SURVIVES a restart — a SECOND worker over a SECOND store finds the backlog and the count", async () => {
    const f = newFixture({ isPeerReachable: async () => false });
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await f.delivery.tick(AGENT, f.holdersFor, NOW);

    // A genuine restart: a new DocumentStore AND a new DocumentDelivery over the same database.
    // The previous version of this test reused both objects, so it asserted "a deferred envelope
    // is due again later" — which an in-memory Map satisfies just as well, and which is the exact
    // thing it was named to disprove.
    const restarted = newFixture({ isPeerReachable: async () => false }, f.db);
    const later = NOW + DELIVERY_BACKOFF_CAP_MS;
    // FANOUT-1: delivery state lives on the per-holder rows now.
    const backlog = restarted.store.pendingHolderDeliveries(AGENT, later);
    expect(backlog).toHaveLength(1);
    // The accumulated attempt count survives too — otherwise the backoff restarts at full rate on
    // every restart, and a daemon in a reconnect loop hammers an unreachable peer forever.
    expect(backlog[0]!.attempts).toBe(1);
    await restarted.delivery.tick(AGENT, restarted.holdersFor, later);
    // The second worker's deferral escalated the SAME per-holder row — count 2, one store, no
    // memory anywhere.
    const after = restarted.store.pendingHolderDeliveries(AGENT, Number.MAX_SAFE_INTEGER);
    expect(after[0]!.attempts).toBe(2);
  });

  it("never re-sends the PEER's own envelopes back at them", async () => {
    const f = newFixture();
    f.store.appendEnvelope(AGENT, envelope(PEER, null));
    // An envelope we RECEIVED is not ours to deliver. Unscoped, a receiver would helpfully bounce
    // every update the sender just sent it straight back.
    expect(await f.delivery.tick(AGENT, f.holdersFor, NOW)).toMatchObject({ attempted: 0 });
  });

  it("does not re-deliver an already-acked envelope", async () => {
    const f = newFixture();
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);
    await f.delivery.tick(AGENT, f.holdersFor, NOW);
    expect(await f.delivery.tick(AGENT, f.holdersFor, NOW + 1)).toMatchObject({ attempted: 0 });
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

    const res = await f.delivery.tick(AGENT, f.holdersFor, NOW);
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

    await f.delivery.tick(AGENT, f.holdersFor, NOW);
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

    await f.delivery.tick(AGENT, f.holdersFor, NOW);
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
    await f.delivery.tick(AGENT, f.holdersFor, NOW);
    await f.delivery.tick(AGENT, f.holdersFor, NOW + DELIVERY_BACKOFF_CAP_MS);

    // FANOUT-1: the counter lives on the per-holder row now.
    const rows = f.store.pendingHolderDeliveries(AGENT, Number.MAX_SAFE_INTEGER);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.attempts).toBe(2);
    // A backoff held in memory is not a backoff: a daemon restarting in a reconnect loop would
    // hammer an unreachable peer at full rate forever — due only AFTER the escalated interval.
    expect(f.store.pendingHolderDeliveries(AGENT, NOW + DELIVERY_BACKOFF_CAP_MS)).toHaveLength(0);
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
      await f.delivery.tick(AGENT, f.holdersFor, at);
      // FANOUT-1: the schedule lives on the per-holder row — pinned by the due boundary, which
      // only the exact value satisfies.
      expect(f.store.pendingHolderDeliveries(AGENT, at + expected! - 1)).toHaveLength(0);
      expect(f.store.pendingHolderDeliveries(AGENT, at + expected!)).toHaveLength(1);
      at += expected!;
    }
  });

  it("an envelope whose next attempt is not yet due is not attempted", async () => {
    const f = newFixture({ isPeerReachable: async () => false });
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await f.delivery.tick(AGENT, f.holdersFor, NOW);
    expect(await f.delivery.tick(AGENT, f.holdersFor, NOW + 1)).toMatchObject({ attempted: 0, deferred: 0 });
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

    const res = await f.delivery.tick(AGENT, f.holdersFor, NOW);
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
    expect(f.events.some((e) => e.event === "document.delivery.no_holders")).toBe(true);
    // Kept — the envelopes are the operator's work, and abandoning them silently is the one
    // outcome an append-only log exists to make impossible …
    expect(f.store.pendingHolderDeliveries(AGENT, NOW + DELIVERY_BACKOFF_CAP_MS)).toHaveLength(1);
    // … but SCHEDULED. The earlier version asserted it was due immediately, which pinned a hot
    // loop: a missing document row is not transient, so those rows stayed due on every tick
    // forever, and being ordered and bounded, the pending window they filled starved every other
    // document — the operator's work elsewhere silently never leaving the machine.
    expect(f.store.pendingHolderDeliveries(AGENT, NOW + 1)).toHaveLength(0);
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
    const first = await f.delivery.tick(AGENT, (d) => (d === DOC ? null : [PEER]), NOW);
    expect(first).toMatchObject({ delivered: 3, failed: 3 });

    // And on the next pass the broken document is no longer due at all, so it stops consuming the
    // bounded window. Left unscheduled, its rows were due on every tick forever and — being
    // ordered and bounded — could fill that window and starve the healthy document indefinitely.
    const second = await f.delivery.tick(AGENT, (d) => (d === DOC ? null : [PEER]), NOW + 1);
    expect(second).toMatchObject({ attempted: 0, failed: 0, delivered: 0 });
  });
});

describe("DocumentDelivery — the session hint (§16.4)", () => {
  it("passes an explicit hint through, and omits it otherwise", async () => {
    const f = newFixture();
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await f.delivery.tick(AGENT, f.holdersFor, NOW, { sessionHints: new Map([[DOC, "session-abc"]]) });
    expect(f.calls[0]!.sessionHint).toBe("session-abc");

    const g = newFixture();
    g.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await g.delivery.tick(AGENT, g.holdersFor, NOW);
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

    const res = await f.delivery.tick(AGENT, f.holdersFor, NOW);
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
    await f.delivery.tick(AGENT, f.holdersFor, NOW);

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
    await f.delivery.tick(AGENT, f.holdersFor, NOW, { correlationId: "corr-1" });

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

    const first = f.delivery.tick(AGENT, f.holdersFor, NOW);
    const second = f.delivery.tick(AGENT, f.holdersFor, NOW);
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

    const res = await f.delivery.tick(AGENT, f.holdersFor, NOW);
    expect(res).toMatchObject({ attempted: 1, sent: 1, delivered: 0, failed: 0 });

    // Two different facts: it LEFT, and the holder has not answered. FANOUT-1: the left-the-
    // machine fact lives on the per-holder row; the envelope row's ack means ALL holders settled.
    expect(f.store.envelopeEverSent(AGENT, e.envelopeHash)).toBe(true);
    expect(f.store.holderHasPending(AGENT, DOC, PEER)).toBe(true);
    expect(f.store.getEnvelopeLog(AGENT, DOC)[0]!.ackedAtMs).toBeNull();
  });

  it("waits the ACK TIMEOUT before sending again — not the failure backoff", async () => {
    const f = newFixture(inFlight());
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));
    await f.delivery.tick(AGENT, f.holdersFor, NOW);

    // The EXACT scheduled time. The earlier version asserted only "not due one millisecond later
    // and due at the cap", which any backoff of 2ms satisfies — and the real post-send wait was
    // ONE SECOND, because the pre-dial failure claim was never overwritten. Every resend appends a
    // leaf to the peer's sealed conversation record, so a second is not a cheap mistake.
    expect(f.store.pendingHolderDeliveries(AGENT, NOW + DELIVERY_ACK_TIMEOUT_MS - 1)).toHaveLength(0);
    expect(f.store.pendingHolderDeliveries(AGENT, NOW + DELIVERY_ACK_TIMEOUT_MS)).toHaveLength(1);
  });

  it("STALLS the document once an envelope has been sent too many times unacked", async () => {
    const f = newFixture(inFlight());
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));

    let at = NOW;
    for (let i = 0; i < DELIVERY_MAX_UNACKED_SENDS; i++) {
      await f.delivery.tick(AGENT, f.holdersFor, at);
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
      f.store.pendingHolderDeliveries(AGENT, at + DELIVERY_ACK_TIMEOUT_MS),
      "the envelope is still queued, so the next tick sends it again — the ceiling stopped nothing",
    ).toHaveLength(0);

    const sendsAtCeiling = f.events.filter((e) => e.event === "document.delivery.sent").length;
    await f.delivery.tick(AGENT, f.holdersFor, at + DELIVERY_ACK_TIMEOUT_MS);
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
    await f.delivery.tick(AGENT, f.holdersFor, NOW);

    // FANOUT-1: the late ack settles THAT HOLDER'S row; the envelope-level record follows
    // because every holder has now answered.
    expect(f.store.ackHolderDelivery(AGENT, DOC, e.envelopeHash, PEER, NOW + 5_000)).toBe(true);
    expect(f.store.envelopeFullySettled(AGENT, e.envelopeHash)).toBe(true);
    expect(f.store.pendingHolderDeliveries(AGENT, NOW + DELIVERY_BACKOFF_CAP_MS)).toHaveLength(0);
  });
});

/**
 * DOD-MP-INVITE-FANOUT-1 — the worker DRAINS owed amendments, and drains them FIRST.
 *
 * The handler now records what is owed; that is worthless unless something delivers it. And the
 * order is not cosmetic: a holder who applies an edit authored at the new epoch BEFORE the
 * amendment that created that epoch refuses the edit as coming from a non-participant — the exact
 * symptom observed live, where a joiner's edits were silently dropped by a holder still at epoch 0.
 */
describe("DOD-MP-INVITE-FANOUT-1 — owed amendments drain, and drain before envelopes", () => {
  const AMEND_EPOCH = 1;

  /** Record an amendment in the chain and owe it to PEER, the way an invite now does. */
  function oweAmendment(f: ReturnType<typeof newFixture>, subject = "cc".repeat(32)): string {
    const body = {
      document_id: DOC, epoch_id: AMEND_EPOCH, prev_amendment_hash: null,
      kind: "add_holder", subject_agent_id: subject,
      property_change: null, state_hash: null, authored_at_ms: 1,
    } as const;
    const hash = documentAmendmentHash(body);
    const hex = Buffer.from(hash).toString("hex");
    const bytes = encodeDocumentAmendment({
      body,
      collection: {
        document_id: DOC, subject_kind: "document_amendment", subject_hash: hash,
        required_signers: ["a".repeat(64)],
        signatures: [{ signer_agent_id: "a".repeat(64), signature: new Uint8Array(64) }],
      },
    });
    f.db.prepare(
      `INSERT INTO document_amendments
         (owner_agent_id, document_id, epoch_id, amendment_hash, received_bytes, recorded_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(AGENT, DOC, AMEND_EPOCH, hex, Buffer.from(bytes), 1);
    f.store.seedAmendmentDeliveries(AGENT, DOC, hex, [PEER], NOW);
    return hex;
  }

  it("an amendment the holder could not take STAYS OWED and is retried — never abandoned", async () => {
    const wire = { up: false };
    const f = newFixture({
      sendBytes: async () =>
        wire.up
          ? { ok: true as const, sessionId: "s", sessionOpened: true }
          : { ok: false as const, reason: "session_sealed" },
    });
    const hex = oweAmendment(f);

    const first = await f.delivery.tick(AGENT, f.holdersFor, NOW);
    expect(first.failed).toBe(1);
    // STILL OWED. This is the whole fix: before it, a failed send left nothing owing anywhere and
    // the holder stayed at the old epoch forever with no error on either side.
    expect(f.store.pendingAmendmentDeliveries(AGENT, NOW + DELIVERY_BACKOFF_CAP_MS)).toHaveLength(1);
    expect(
      f.events.some((e) => e.event === "document.amendment.delivery_failed"),
      "a membership change that cannot be delivered yet is a retry, and must say so",
    ).toBe(true);

    // The holder comes back. No operator action anywhere.
    wire.up = true;
    const second = await f.delivery.tick(AGENT, f.holdersFor, NOW + DELIVERY_BACKOFF_CAP_MS);
    // SENT, not delivered. The bytes reached their daemon; whether it RECORDED them is a separate
    // fact and the receiver can refuse (a chain gap throws there and answers nothing). Counting
    // this as delivered is what let the original defect through the new machinery.
    expect(second.sent).toBe(1);
    expect(f.events.some((e) => e.event === "document.amendment.sent")).toBe(true);

    // STILL OWED, deliberately — re-offered after the ack timeout until something PROVES receipt.
    const stillOwed = f.store.pendingAmendmentDeliveries(
      AGENT, NOW + DELIVERY_BACKOFF_CAP_MS + DELIVERY_ACK_TIMEOUT_MS + 1,
    );
    expect(stillOwed).toHaveLength(1);
    expect(hex).toHaveLength(64);
  });

  it("PROOF BY EPOCH settles it — a holder that acks content at that epoch demonstrably has it", async () => {
    const f = newFixture({
      sendBytes: async () => ({ ok: true as const, sessionId: "s", sessionOpened: true }),
      deliver: async () => ({ ok: true as const, admitted: true, sessionId: "s", sessionOpened: true }),
    });
    oweAmendment(f);
    await f.delivery.tick(AGENT, f.holdersFor, NOW);
    expect(f.store.pendingAmendmentDeliveries(AGENT, NOW + DELIVERY_ACK_TIMEOUT_MS + 1)).toHaveLength(1);

    // An envelope authored at the amendment's epoch, which this holder ACKS. The inbound epoch gate
    // refuses anything whose epoch does not match the receiver's own derived arrangement, so their
    // answer about this envelope is proof they applied the amendment that created the epoch.
    const e = { ...envelope(AGENT, null), epochId: AMEND_EPOCH };
    f.store.appendEnvelope(AGENT, e);
    f.store.seedDeliveries(AGENT, DOC, e.envelopeHash, [PEER], NOW);
    await f.delivery.tick(AGENT, f.holdersFor, NOW + DELIVERY_ACK_TIMEOUT_MS + 2);

    // Settled for real — without an amendment ack frame, and without ever claiming that bytes
    // arriving meant governance applied.
    expect(f.store.pendingAmendmentDeliveries(AGENT, NOW + DELIVERY_ACK_TIMEOUT_MS * 4)).toEqual([]);
    expect(f.events.some((e2) => e2.event === "document.amendment.confirmed_by_epoch")).toBe(true);
  });

  it("a RELAY-PARKED send is not treated as delivered", async () => {
    const f = newFixture({
      sendBytes: async () => ({ ok: true as const, sessionId: "s", sessionOpened: true, parked: true }),
    });
    oweAmendment(f);
    const res = await f.delivery.tick(AGENT, f.holdersFor, NOW);
    // The relay took it because the holder had no live counterparty. If they never drain it and the
    // debt has been cleared, the membership change is gone with both surfaces reporting success.
    expect(res.failed).toBe(1);
    expect(res.sent).toBe(0);
    const ev = f.events.find((e) => e.event === "document.amendment.delivery_failed");
    expect(ev!.fields["reason"]).toBe("relay_parked");
    expect(f.store.pendingAmendmentDeliveries(AGENT, NOW + DELIVERY_BACKOFF_CAP_MS * 2)).toHaveLength(1);
  });

  it("an EARLIER unacked amendment blocks a later one — no chain gap at the receiver", async () => {
    const f = newFixture({
      sendBytes: async () => ({ ok: false as const, reason: "session_sealed", detail: "sealed" }),
    });
    const first = oweAmendment(f, "cc".repeat(32));
    // A second amendment, seeded later and therefore due immediately while the first is backed off.
    const body2 = {
      document_id: DOC, epoch_id: AMEND_EPOCH + 1, prev_amendment_hash: first,
      kind: "add_holder", subject_agent_id: "dd".repeat(32),
      property_change: null, state_hash: null, authored_at_ms: 2,
    } as const;
    const h2 = documentAmendmentHash(body2);
    const hex2 = Buffer.from(h2).toString("hex");
    f.db.prepare(
      `INSERT INTO document_amendments
         (owner_agent_id, document_id, epoch_id, amendment_hash, received_bytes, recorded_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(AGENT, DOC, AMEND_EPOCH + 1, hex2, Buffer.from(encodeDocumentAmendment({
      body: body2,
      collection: {
        document_id: DOC, subject_kind: "document_amendment", subject_hash: h2,
        required_signers: ["a".repeat(64)],
        signatures: [{ signer_agent_id: "a".repeat(64), signature: new Uint8Array(64) }],
      },
    })), 2);
    f.store.seedAmendmentDeliveries(AGENT, DOC, hex2, [PEER], NOW + 1);

    await f.delivery.tick(AGENT, f.holdersFor, NOW);
    // Epoch 2 must NOT go out first. It would be refused with `document_amendment_chain_gap` —
    // "an out-of-order arrival is retried by its sender, never buffered silently" — and the
    // ordering that guarantees it is head-of-line per (document, holder), not creation order among
    // whichever rows happen to be due.
    const due = f.store.pendingAmendmentDeliveries(AGENT, NOW + DELIVERY_BACKOFF_CAP_MS * 2);
    expect(due).toHaveLength(1);
    expect(due[0]!.epochId).toBe(AMEND_EPOCH);
  });

  it("the amendment goes out BEFORE the envelope in the same pass", async () => {
    const order: string[] = [];
    const f = newFixture({
      sendBytes: async () => {
        order.push("amendment");
        return { ok: true as const, sessionId: "s", sessionOpened: true };
      },
      deliver: async () => {
        order.push("envelope");
        return { ok: true as const, admitted: true, sessionId: "s", sessionOpened: true };
      },
    });
    oweAmendment(f);
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));

    await f.delivery.tick(AGENT, f.holdersFor, NOW);
    // Reverse this and the holder receives an edit authored at an epoch they have never heard of,
    // and refuses it. Ordering is the guarantee, not a coincidence of which queue happened to be
    // read first.
    expect(order).toEqual(["amendment", "envelope"]);
  });

  it("a holder the chain no longer contains is owed nothing — and is not dialed", async () => {
    const sends: string[] = [];
    const f = newFixture({
      sendBytes: async (input) => {
        sends.push(input.peerAgentId);
        return { ok: true as const, sessionId: "s", sessionOpened: true };
      },
    });
    const hex = oweAmendment(f);
    // A SECOND holder who IS still in the chain, owed the same amendment. Without this the test
    // passes against an implementation that acks every row and never sends anything at all —
    // "nothing was dialed" is exactly what a do-nothing loop achieves.
    const H2 = "ee".repeat(32);
    f.store.seedAmendmentDeliveries(AGENT, DOC, hex, [H2], NOW);

    // PEER is gone from the derived set — governance must not be sprayed at whoever was last known.
    await f.delivery.tick(AGENT, () => [H2], NOW);
    expect(sends, "the remaining holder is dialed; the departed one is not").toEqual([H2]);
    expect(f.store.pendingAmendmentDeliveries(AGENT, NOW + DELIVERY_BACKOFF_CAP_MS)
      .map((p) => p.holderAgentId)).not.toContain(PEER);
    // RETIRED, NOT ACKED — the durable record must not claim a delivery that never happened.
    const row = f.db.prepare(
      `SELECT acked_at, retired_at FROM document_amendment_deliveries
        WHERE owner_agent_id = ? AND holder_agent_id = ?`,
    ).get(AGENT, PEER) as { acked_at: number | null; retired_at: number | null };
    expect(row.retired_at).not.toBeNull();
    expect(row.acked_at).toBeNull();
    expect(f.events.some((e) => e.event === "document.amendment.holder_retired")).toBe(true);
  });

  it("an underivable chain DEFERS the amendment rather than guessing a recipient", async () => {
    const sends: string[] = [];
    const f = newFixture({
      sendBytes: async (input) => {
        sends.push(input.peerAgentId);
        return { ok: true as const, sessionId: "s", sessionOpened: true };
      },
    });
    oweAmendment(f);
    // holdersFor === null means "the document row is gone or the chain does not derive". Sending
    // to the last-known holder there would be the silent-fallback shape this project forbids;
    // dropping the row would lose the membership change. It stays owed.
    await f.delivery.tick(AGENT, () => null, NOW);
    expect(sends).toEqual([]);
    // STILL OWED — dropping the row would lose the membership change.
    expect(
      f.store.pendingAmendmentDeliveries(AGENT, NOW + DELIVERY_BACKOFF_CAP_MS * 2),
    ).toHaveLength(1);
    // AND IT SAYS SO. Without this assertion the test passes against a drain loop that does
    // nothing at all — it was asserting the behaviour of a no-op. The envelope pass logs
    // `no_holders` only for documents that also have pending envelopes, so a document whose content
    // is fully acked would sit here re-scanned every tick with nothing said anywhere.
    const ev = f.events.find((e) => e.event === "document.amendment.holders_underivable");
    expect(ev, "a permanently stuck membership change must not be silent").toBeDefined();
    expect(ev!.fields["holderAgentId"]).toBe(PEER);
    // And it is not re-scanned every tick — it is scheduled at the cap.
    expect(f.store.pendingAmendmentDeliveries(AGENT, NOW + 1)).toEqual([]);
  });
});

/**
 * DOD-MP-INVITE-FANOUT-1, clause 6 — THE UPGRADE PATH, against a POPULATED database.
 *
 * §2e: the daemon's migration mechanism is client-side and its failures are unrecoverable on an
 * operator's machine, so every schema change is tested against a database that already has rows —
 * never a fresh one. A fresh-DB test cannot fail the way a real upgrade fails.
 */
describe("DOD-MP-INVITE-FANOUT-1 — upgrading a genuinely PRE-MIGRATION populated database", () => {
  it("a database with NO amendment-delivery table keeps its content backlog and gains the table", async () => {
    const db = new DatabaseSync(":memory:");
    db.exec("PRAGMA foreign_keys = ON");

    // A daemon on the OLD build: real documents, a real content backlog.
    const before = newFixture({}, db);
    before.store.createDocument({
      documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
    const old = envelope(AGENT, null);
    before.store.appendEnvelope(AGENT, old);
    before.store.seedDeliveries(AGENT, DOC, old.envelopeHash, [PEER], NOW);

    // NOW MAKE IT ACTUALLY PRE-MIGRATION. The first version of this test asserted nothing about
    // migration: `DocumentStore`'s constructor creates `document_amendment_deliveries`
    // unconditionally, so its "before" store already had the new schema and the test would have
    // passed on a build with no migration at all. Dropping the table reproduces the real starting
    // state — a populated database that has never seen this change.
    db.exec("DROP TABLE document_amendment_deliveries");
    const present = () =>
      (db.prepare(
        "SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name='document_amendment_deliveries'",
      ).get() as { n: number }).n;
    expect(present(), "the premise: the table must be ABSENT before the upgrade").toBe(0);

    const owedBefore = before.store.pendingHolderDeliveries(AGENT, NOW);
    expect(owedBefore.length, "the pre-upgrade backlog must be non-empty or this proves nothing")
      .toBeGreaterThan(0);

    // THE UPGRADE: a new store opens the same database, exactly as a restarted daemon does.
    const after = newFixture({}, db);

    // The migration ran, on a populated database, with no data step.
    expect(present()).toBe(1);
    // And the old backlog is untouched — not dropped, not duplicated, same holder.
    const owedAfter = after.store.pendingHolderDeliveries(AGENT, NOW);
    expect(owedAfter.map((p) => p.envelope.envelopeHash))
      .toEqual(owedBefore.map((p) => p.envelope.envelopeHash));
    expect(owedAfter.every((p) => p.holderAgentId === PEER)).toBe(true);

    // The content delivery still goes out on the upgraded store — the new queue sitting in front of
    // it does not break the pass.
    const res = await after.delivery.tick(AGENT, after.holdersFor, NOW);
    expect(res.delivered + res.sent).toBeGreaterThan(0);
  });

  it("an owed amendment SURVIVES a restart — the debt is on disk, like the backlog it replaces", async () => {
    const db = new DatabaseSync(":memory:");
    db.exec("PRAGMA foreign_keys = ON");
    const first = newFixture({
      sendBytes: async () => ({ ok: false as const, reason: "session_sealed", detail: "sealed" }),
    }, db);
    first.store.createDocument({
      documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
    const body = {
      document_id: DOC, epoch_id: 1, prev_amendment_hash: null,
      kind: "add_holder", subject_agent_id: "cc".repeat(32),
      property_change: null, state_hash: null, authored_at_ms: 1,
    } as const;
    const hash = documentAmendmentHash(body);
    const hex = Buffer.from(hash).toString("hex");
    db.prepare(
      `INSERT INTO document_amendments
         (owner_agent_id, document_id, epoch_id, amendment_hash, received_bytes, recorded_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(AGENT, DOC, 1, hex, Buffer.from(encodeDocumentAmendment({
      body,
      collection: {
        document_id: DOC, subject_kind: "document_amendment", subject_hash: hash,
        required_signers: ["a".repeat(64)],
        signatures: [{ signer_agent_id: "a".repeat(64), signature: new Uint8Array(64) }],
      },
    })), 1);
    first.store.seedAmendmentDeliveries(AGENT, DOC, hex, [PEER], NOW);
    await first.delivery.tick(AGENT, first.holdersFor, NOW);

    // THE DAEMON RESTARTS. Clause 2 claims the holder still receives it "after a daemon restart,
    // with no operator action", and nothing pinned that — an in-memory debt would evaporate here
    // and the membership change would be lost exactly as it was before the fix.
    const reopened = newFixture({
      sendBytes: async () => ({ ok: true as const, sessionId: "s", sessionOpened: true }),
    }, db);
    const owed = reopened.store.pendingAmendmentDeliveries(AGENT, NOW + DELIVERY_BACKOFF_CAP_MS * 2);
    expect(owed.map((o) => o.amendmentHash)).toEqual([hex]);

    const res = await reopened.delivery.tick(AGENT, reopened.holdersFor, NOW + DELIVERY_BACKOFF_CAP_MS * 2);
    expect(res.sent).toBe(1);
  });
});
