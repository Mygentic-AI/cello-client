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

    // ...and the backoff is gone afterwards, not merely bypassed once.
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
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 0, skippedBackoff: 1 });

    f.clock.now += RECONCILE_BACKOFF_BASE_MS;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });

    // ...and the ladder DOUBLES, so an offer nobody takes up goes quiet rather than settling
    // into a fixed drumbeat.
    f.clock.now += RECONCILE_BACKOFF_BASE_MS + 1;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 0, skippedBackoff: 1 });
    f.clock.now += RECONCILE_BACKOFF_BASE_MS;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });
  });

  it("a NEW pending change is a trigger — it does not wait out the ladder", async () => {
    let signature = "c:author:1";
    const f = fixture({ pendingFor: () => signature });
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });
    f.clock.now += 1_000;
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 0, skippedBackoff: 1 });

    signature = "c:author:2"; // we authored another entry
    f.clock.now += 1_000;
    expect(
      await f.scheduler.sweep(OWNER),
      "a real pending change was held behind the backoff a stale one had armed",
    ).toMatchObject({ attempted: 1 });
    expect(f.sent).toHaveLength(2);
  });

  it("the frame carries ONLY the documents with something pending", async () => {
    const f = fixture({
      sweepTargets: () => new Map([[PEER, ["d1", "d2", "d3"]]]),
      pendingFor: (_o, documentId) => (documentId === "d2" ? "c:author:1" : null),
    });
    expect(await f.scheduler.sweep(OWNER)).toMatchObject({ attempted: 1 });
    expect(f.sent).toHaveLength(1);
    expect(f.sent[0]!.docs).toEqual(["d2"]);
  });

  it("onReachable still asks about EVERYTHING — reachability is where the pull lives now", async () => {
    // Suppressing the timer removes the periodic PULL: `pendingFor` can only see what we hold
    // that they lack, never what they hold that we lack. The pull moves onto a real event — a
    // session with them coming up — and must not inherit the pending gate.
    const f = fixture({
      sweepTargets: () => new Map([[PEER, ["d1", "d2"]]]),
      pendingFor: () => null,
    });
    await f.scheduler.onReachable(OWNER, PEER);
    expect(f.sent).toHaveLength(1);
    expect(f.sent[0]!.docs).toEqual(["d1", "d2"]);
  });
});
