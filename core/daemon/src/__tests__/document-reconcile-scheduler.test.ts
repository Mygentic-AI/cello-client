/**
 * SYNC-P5 (R39–R43) — the scheduler decides MOMENTS, never correctness. Every piece of its state
 * is volatile: these tests drive a fake clock and a fake transport and assert exactly when an
 * exchange is attempted, suppressed, backed off, and force-released.
 */
import { describe, it, expect } from "vitest";
import {
  ReconcileScheduler,
  RECONCILE_BACKOFF_BASE_MS,
  RECONCILE_BACKOFF_CAP_MS,
  RECONCILE_INFLIGHT_BOUND_MS,
  RECONCILE_BATCH_CAP,
  type ReconcileSchedulerDeps,
} from "../document-reconcile-scheduler.js";
import type { Logger } from "./../types.js";

const OWNER = "aa".repeat(32);
const PEER = "bb".repeat(32);

function recordingLogger(): { logger: Logger; events: string[] } {
  const events: string[] = [];
  const push = (event: string) => void events.push(event);
  const logger = { debug: push, info: push, warn: push, error: push } as unknown as Logger;
  return { logger, events };
}

function fixture(over: Partial<ReconcileSchedulerDeps> = {}) {
  const { logger, events } = recordingLogger();
  const clock = { now: 1_700_000_000_000 };
  const sent: Array<{ peer: string; docs: readonly string[] }> = [];
  const deps: ReconcileSchedulerDeps = {
    now: () => clock.now,
    logger,
    sweepTargets: () => new Map([[PEER, ["d1"]]]),
    pendingFor: () => "g:x:1",
    initiateReconcile: async (_o, peer, docs) => {
      sent.push({ peer, docs });
      return { ok: true };
    },
    ...over,
  };
  return { scheduler: new ReconcileScheduler(deps), clock, sent, events };
}

describe("the sweep (R39 trigger 3, R43 bounds)", () => {
  it("attempts a party with something pending, and skips one with nothing", async () => {
    const f = fixture();
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });
    expect(f.sent).toHaveLength(1);

    const quiet = fixture({ pendingFor: () => null });
    expect(await quiet.scheduler.sweep(OWNER)).toMatchObject({
      attempted: 0,
      skippedNothingPending: 1,
    });
    expect(quiet.sent).toHaveLength(0);
  });

  it("a party that does not answer is backed off, doubling to the cap — and a sweep inside the window skips", async () => {
    const f = fixture({
      initiateReconcile: async () => ({ ok: false, reason: "peer_offline" }),
    });
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1, failed: 1 });
    // Inside the first backoff window: skipped, not re-dialed.
    f.clock.now += RECONCILE_BACKOFF_BASE_MS - 1;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 0, skippedBackoff: 1 });
    // Past it: attempted again, failure doubles the window.
    f.clock.now += 2;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1, failed: 1 });
    f.clock.now += RECONCILE_BACKOFF_BASE_MS * 2 - 2;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ skippedBackoff: 1 });
    // The cap holds: many failures never exceed it.
    for (let i = 0; i < 10; i++) {
      f.clock.now += RECONCILE_BACKOFF_CAP_MS + 1;
      await f.scheduler.sweep(OWNER);
    }
    f.clock.now += RECONCILE_BACKOFF_CAP_MS + 1;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });
  });

  it("a wedged in-flight mark is honored inside its bound and RELEASED LOUDLY past it (R42)", async () => {
    let resolveHang!: (v: { ok: true }) => void;
    const hang = new Promise<{ ok: true }>((r) => { resolveHang = r; });
    const f = fixture({ initiateReconcile: () => hang });
    const first = f.scheduler.sweep(OWNER); // parks in-flight, never settles this round
    await new Promise((r) => setTimeout(r, 10));
    // Inside the bound: the mark is honored.
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ skippedInFlight: 1 });
    // Past the bound: released, loudly, and the party is attempted again.
    f.clock.now += RECONCILE_INFLIGHT_BOUND_MS + 1;
    resolveHang({ ok: true });
    await first;
    let hung = true;
    const neverSettles = new Promise<{ ok: true }>(() => {});
    const wedged = fixture({
      initiateReconcile: () => (hung ? neverSettles : Promise.resolve({ ok: true as const })),
    });
    void wedged.scheduler.sweep(OWNER);
    await new Promise((r) => setTimeout(r, 10));
    wedged.clock.now += RECONCILE_INFLIGHT_BOUND_MS + 1;
    hung = false;
    expect(await wedged.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });
    expect(wedged.events).toContain("document.reconcile.inflight_expired");
  });

  it("chunks one party's documents at the R16 cap", async () => {
    const docs = Array.from({ length: RECONCILE_BATCH_CAP + 3 }, (_v, i) => `d${i}`);
    const f = fixture({ sweepTargets: () => new Map([[PEER, docs]]) });
    await f.scheduler.sweep(OWNER);
    expect(f.sent).toHaveLength(2);
    expect(f.sent[0]!.docs).toHaveLength(RECONCILE_BATCH_CAP);
    expect(f.sent[1]!.docs).toHaveLength(3);
  });
});

describe("onReachable (R39 trigger 2)", () => {
  it("fires immediately and RESETS backoff — the backoff modeled silence, and they just answered", async () => {
    let answer = false;
    const f = fixture({
      initiateReconcile: async (_o, peer, docs) => {
        f.sent.push({ peer, docs });
        return answer ? { ok: true } : { ok: false, reason: "peer_offline" };
      },
    });
    await f.scheduler.sweep(OWNER); // fails → backoff armed
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ skippedBackoff: 1 });
    answer = true;
    await f.scheduler.onReachable(OWNER, PEER); // reachability overrides the backoff
    expect(f.sent).toHaveLength(2);
  });

  it("does nothing for a party with no shared documents", async () => {
    const f = fixture({ sweepTargets: () => new Map() });
    await f.scheduler.onReachable(OWNER, PEER);
    expect(f.sent).toHaveLength(0);
  });
});

describe("a REFUSAL is an answer, and it must slow the asking down", () => {
  // Measured 2026-08-17: 321 reconcile attempts against two documents in 85 minutes, refused
  // every time, zero successes, ~4 dials a minute forever. The backoff never engaged because
  // `allOk` reports whether the FRAME WAS SENT, not whether reconcile succeeded — so a peer
  // answering "no, and never again" was indistinguishable from a peer answering fine.
  //
  // R41 holds: this DELAYS an exchange, it never forbids one. A terminal refusal goes straight
  // to the cap rather than being retired, so nothing here can permanently forbid an exchange
  // that a later entry might make admissible.
  it("a NON-TERMINAL refusal backs the party off instead of retrying at full speed", async () => {
    const f = fixture();
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });

    f.scheduler.noteRefusal(OWNER, PEER, false);
    f.clock.now += 1_000;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 0, skippedBackoff: 1 });

    // Past the first backoff step it is asked again — a refusal delays, it does not forbid.
    f.clock.now += RECONCILE_BACKOFF_BASE_MS;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });
  });

  it("a TERMINAL refusal goes straight to the cap — 'nothing further to reconcile' is not a retry", async () => {
    const f = fixture();
    f.scheduler.noteRefusal(OWNER, PEER, true);

    // Just under the cap: still suppressed. This is the 105-refusals case.
    f.clock.now += RECONCILE_BACKOFF_CAP_MS - 1_000;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 0, skippedBackoff: 1 });

    // Past the cap it asks once more. R41: delayed, never forbidden.
    f.clock.now += 2_000;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });
  });

  it("an explicit reachability signal still CLEARS a refusal backoff — R39's second trigger outranks it", async () => {
    const f = fixture();
    f.scheduler.noteRefusal(OWNER, PEER, true);
    await f.scheduler.onReachable(OWNER, PEER);
    expect(f.sent).toHaveLength(1);
  });
});

describe("DOD-M12B-DELIVERY-QUIET-1: what the reachability trigger actually does", () => {
  /**
   * The stakes behind exempting delivery-opened sessions, asserted here rather than inferred there.
   *
   * If `onReachable` were a mild nudge, suppressing it for machine-opened sessions would be
   * over-engineering. It is not: it wipes the backoff outright and sweeps immediately. So a session
   * the delivery worker itself opened re-opens the loop that a refusal had just closed — which is
   * the circularity, in two lines.
   */
  it("onReachable WIPES a backoff a TERMINAL refusal just set, and sweeps at once", async () => {
    const f = fixture();
    f.scheduler.noteRefusal(OWNER, PEER, true);          // terminal → straight to the cap
    f.clock.now += 1_000;                                 // nowhere near the cap
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 0, skippedBackoff: 1 });

    const before = f.sent.length;
    await f.scheduler.onReachable(OWNER, PEER);
    expect(f.sent.length, "onReachable did not wait out the cap — that is the behaviour being suppressed")
      .toBeGreaterThan(before);

    // ...and the REFUSAL backoff is gone afterwards, not merely bypassed once. What remains is
    // the one quiet step onReachable's own offer just armed (DOD-DOC-PUSH-NOT-POLL-1) — 30
    // seconds, not the refusal's fifteen minutes. The distinction is the point: the thing the
    // machine-opened session must not be able to wipe is a peer saying no.
    f.clock.now += RECONCILE_BACKOFF_BASE_MS + 1;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });
  });
});


describe("DOD-DOC-PUSH-NOT-POLL-1: the timer is not a reason to speak", () => {
  /**
   * Measured on the live store 2026-08-18: three agents, 30 documents between them, and the
   * believed-current suppressor needed EVERY shared document to read in_sync AND to have been
   * exchanged within ten minutes. One stale timestamp — the newest was days old — kept the whole
   * party, all fourteen of its documents, sweeping every 120 seconds forever. Each of those
   * frames took a position in the CONVERSATION's hash chain: 34 positions on one live session,
   * 2 of them real messages, and the seal refused `session_incomplete`.
   *
   * The rule replacing it: we speak when we HOLD something the party has not confirmed
   * receiving. Nothing pending, no frame, no position consumed.
   */
  it("a party with nothing pending is NEVER asked, however long it has been", async () => {
    const f = fixture({ pendingFor: () => null });
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({
      attempted: 0,
      skippedNothingPending: 1,
    });
    // The old belief EXPIRED here and the sweep asked again. Silence is no longer a reason.
    f.clock.now += 24 * 60 * 60_000;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 0 });
    expect(f.sent, "a quiet party was asked anyway — the bare timer is still driving").toHaveLength(
      0,
    );
  });

  it("the SAME unchanged pending set is offered once, then backed off — not re-offered every tick", async () => {
    // The send SUCCEEDS every time: the frame goes out, the party simply never acts on it (an
    // invitation nobody accepted is the live case). `allOk` says the frame was sent, so the old
    // code reset nextAttemptMs to now and asked again on the very next tick, forever.
    const f = fixture({ pendingFor: () => "g:author:7" });
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });

    f.clock.now += 1_000;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 0, skippedQuiet: 1 });

    f.clock.now += RECONCILE_BACKOFF_BASE_MS;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });

    // ...and the ladder DOUBLES, so an offer nobody takes up goes quiet rather than settling
    // into a fixed drumbeat.
    f.clock.now += RECONCILE_BACKOFF_BASE_MS + 1;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 0, skippedQuiet: 1 });
    f.clock.now += RECONCILE_BACKOFF_BASE_MS;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });
  });

  it("a NEW pending change is a trigger — it does not wait out the ladder", async () => {
    let signature = "c:author:1";
    const f = fixture({ pendingFor: () => signature });
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });
    f.clock.now += 1_000;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 0, skippedQuiet: 1 });

    signature = "c:author:2"; // we authored another entry
    f.clock.now += 1_000;
    expect(
      await f.scheduler.sweep(OWNER),
      "a real pending change was held behind the backoff a stale one had armed",
    ).toMatchObject({ attempted: 1 });
    expect(f.sent).toHaveLength(2);
  });

  it("ONE pending document justifies the frame, and the frame then carries them ALL", async () => {
    // The gate is on the DECISION, not on the frame's contents. A block is positions only and the
    // responder answers solely where a side is ahead, so a quiet document riding along costs
    // bytes — never a frame, never a position — and keeps its pull. Narrowing the list would
    // have bought nothing and cost that.
    const f = fixture({
      sweepTargets: () => new Map([[PEER, ["d1", "d2", "d3"]]]),
      pendingFor: (_o, documentId) => (documentId === "d2" ? "c:author:1" : null),
    });
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });
    expect(f.sent).toHaveLength(1);
    expect(f.sent[0]!.docs).toEqual(["d1", "d2", "d3"]);
  });

  it("REGRESSION GUARD (not this unit's change): onReachable ignores the pending gate entirely", async () => {
    // Named as a guard on purpose — it passes against the pre-change scheduler too, because
    // onReachable never consulted the old suppressor either. It is here so that a later
    // "why not gate this one as well?" has to delete an assertion to do it.
    //
    // The stake: `pendingFor` sees only what we hold that they lack. Take the gate off the timer
    // and this is the one remaining place that can discover the other direction.
    const f = fixture({
      sweepTargets: () => new Map([[PEER, ["d1", "d2"]]]),
      pendingFor: () => null,
    });
    await f.scheduler.onReachable(OWNER, PEER);
    expect(f.sent).toHaveLength(1);
    expect(f.sent[0]!.docs).toEqual(["d1", "d2"]);
  });

  it("onReachable RESETS the quiet ladder — a party parked at the cap is asked at once", async () => {
    // Covers onReachable's state resets, which had no test: delete all four lines and every other
    // test still passed. Walk the ladder to the 15-minute cap, then let them become reachable.
    const f = fixture({ pendingFor: () => "g:author:9" });
    for (let i = 0; i < 12; i++) {
      f.clock.now += RECONCILE_BACKOFF_CAP_MS + 1;
      await f.scheduler.sweep(OWNER);
    }
    const parked = f.sent.length;
    expect(parked, "the ladder never let the party speak at all").toBeGreaterThan(1);
    // Deep in the ladder: a quarter of an hour of silence ahead of it.
    f.clock.now += RECONCILE_BACKOFF_CAP_MS - 1_000;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 0, skippedQuiet: 1 });

    await f.scheduler.onReachable(OWNER, PEER);
    expect(f.sent.length, "onReachable did not clear the quiet ladder").toBe(parked + 1);
    // ...and it RECORDED what it offered, so the next tick does not re-offer the same holding.
    // Nulling the record instead cost one duplicate frame at every session establishment.
    f.clock.now += 1_000;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 0, skippedQuiet: 1 });
  });

  it("a new pending change does NOT step over a REFUSAL backoff — only over the quiet one", async () => {
    // The two deadlines are separate for exactly this reason, and nothing pinned it. An
    // optimisation that computes the holding first, to skip the state lookup, reorders the two
    // blocks and silently reopens the 321-refusals-in-85-minutes defect with every test green.
    let signature = "c:author:1";
    const f = fixture({ pendingFor: () => signature });
    f.scheduler.noteRefusal(OWNER, PEER, true); // terminal → straight to the 15-minute cap

    signature = "c:author:2"; // we authored something new; the peer still said no
    f.clock.now += 1_000;
    expect(
      await f.scheduler.sweep(OWNER),
      "a local edit stepped over a refusal backoff — that is the retry storm, re-armed",
    ).toMatchObject({ attempted: 0, skippedBackoff: 1 });
    expect(f.sent).toHaveLength(0);
  });
});
