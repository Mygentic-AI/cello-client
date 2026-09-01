/**
 * DOD-M15-ENDORSE-RETRY-1 — a trust signal survives the directory node going away.
 *
 * THE DEFECT: an operator mints a trust signal, the one directory node their daemon holds a
 * signaling stream to is down or restarting, and the command fails and it is over. Nothing queues
 * it, nothing retries it, and the operator has to notice and re-run it themselves. The consortium
 * has three nodes; surviving one of them being unavailable is the entire reason there are three.
 *
 * THE FIX IS THE RETRY, NOT THE ROUTING. `sendSealedSubmission`'s own header rules out a
 * client-side multi-node write: the daemon holds ONE signaling stream, the SignalingManager's
 * reconnect is the failover, and a retry across it is safe because `submission_id` is derived from
 * the plaintext body — the same body produces the same id, so a second node stores it once and the
 * portal mints once.
 *
 * WHAT THESE TESTS ARE ABOUT, clause by clause:
 *   1. a send that reached nobody is retried after reconnect, with no operator action;
 *   3. a submission the node REFUSED ON ITS MERITS is never enqueued at all;
 *   4. the retry is bounded on TWO axes, each with its own named give-up reason and next step;
 *   5. while retrying, the surface says so.
 * Clause 2 — the same submission reaching two nodes is stored once and minted once — is asserted
 * where those two properties actually live, not here: per-node storage in trustless-cello's
 * `m10b-queue-1-v51-submission-queue` ("a retry of the same body is a STRICT no-op"), and mint-once
 * across nodes in cello-portal's `m10b-ingress-1-drain-loop`.
 *
 * REVERT TESTS (each run, each reddens for its own reason):
 *   - drop `signaling_reconnecting` from RETRYABLE → clause 1 fails: nothing is ever enqueued.
 *   - add `submission_refused_by_node` to RETRYABLE → clause 3 fails: a refusal is retried.
 *   - make a transport failure spend the attempt budget → the window test gives up as
 *     `attempts_exhausted` instead of `retry_window_elapsed`, so the operator is told the wrong
 *     thing about a node that was merely flapping.
 */
import { describe, it, expect } from "vitest";
import {
  SubmissionRetryQueue,
  isRetryableSendFailure,
  type PendingSubmission,
} from "../submission-retry.js";
import type { SendSubmissionResult, SubmissionSendFailure } from "../signal-submission.js";
import type { Logger } from "../types.js";

interface LogEvent { event: string; ctx: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const push = (event: string, ctx?: Record<string, unknown>): void => { events.push({ event, ctx: ctx ?? {} }); };
  return { logger: { debug: push, info: push, warn: push, error: push }, events };
}

/**
 * A hand-cranked clock + scheduler, taken from `msg-013-restart-seal`. Nothing fires until
 * `advance` reaches its deadline, so every assertion is about WHEN the queue chose to act rather
 * than about how fast a real timer happened to run.
 */
function makeClock() {
  let now = 1_000_000;
  let seq = 0;
  const pending = new Map<number, { at: number; fn: () => void }>();
  return {
    now: () => now,
    schedule(fn: () => void, ms: number) {
      const id = seq++;
      pending.set(id, { at: now + ms, fn });
      return { cancel: () => { pending.delete(id); } };
    },
    async advance(ms: number): Promise<void> {
      const target = now + ms;
      for (;;) {
        let nextId: number | null = null;
        let nextAt = Infinity;
        for (const [id, t] of pending) if (t.at <= target && t.at < nextAt) { nextAt = t.at; nextId = id; }
        if (nextId === null) break;
        const task = pending.get(nextId)!;
        pending.delete(nextId);
        now = task.at;
        task.fn();
        for (let i = 0; i < 20; i++) await Promise.resolve();
      }
      now = target;
      for (let i = 0; i < 20; i++) await Promise.resolve();
    },
    /** How many timers are still armed. Lets a test assert that stop() left NOTHING behind, rather
     *  than only that nothing was sent. */
    pendingCount: () => pending.size,
  };
}

const CIPHERTEXT = new Uint8Array([1, 2, 3, 4]);

function item(overrides: Partial<PendingSubmission> = {}): PendingSubmission {
  return {
    agentName: "Alice",
    agentId: "agent-alice",
    submissionId: "aa".repeat(32),
    intakeKeyId: "intake-0",
    ciphertext: CIPHERTEXT,
    op: "submit",
    subject: "bb".repeat(32),
    ...overrides,
  };
}

function fail(reason: SubmissionSendFailure): SendSubmissionResult {
  return { ok: false, reason, guidance: `guidance for ${reason}` };
}

describe("DOD-M15-ENDORSE-RETRY-1 — classification (clauses 1 and 3)", () => {
  /**
   * THE VALUES COME FROM THE UNION, NOT FROM WHAT CAME TO MIND. `SubmissionSendFailure` enumerates
   * exactly six members; every one is named here, so a member added later without a decision about
   * it fails this test rather than defaulting silently into one bucket.
   */
  it("retries the four failures that are NOT a verdict on the submission", () => {
    expect(isRetryableSendFailure("directory_unreachable")).toBe(true);
    expect(isRetryableSendFailure("signaling_reconnecting")).toBe(true);
    expect(isRetryableSendFailure("signaling_lost")).toBe(true);
    // The node never decoded the frame. Nodes deploy independently per region, so the reconnect
    // this retry rides may well land on one that has the frame kind — which is the whole failover
    // case this unit exists for.
    expect(isRetryableSendFailure("submission_unsupported_by_node")).toBe(true);
    // The transport handed the frame over and no ack came back. Storage is UNKNOWN, not refused —
    // and re-sending is safe because the id is content-derived.
    expect(isRetryableSendFailure("submission_write_timeout")).toBe(true);
  });

  it("NEVER retries a submission the node refused on its merits (clause 3)", () => {
    // The node decoded it, evaluated it, and said no. A retry cannot change that answer, and a
    // machine asking again is badgering a node that already decided.
    expect(isRetryableSendFailure("submission_refused_by_node")).toBe(false);
  });
});

describe("DOD-M15-ENDORSE-RETRY-1 — the retry (clauses 1, 4, 5)", () => {
  function harness(opts: {
    outcomes: SendSubmissionResult[];
    maxAttempts?: number;
    retryWindowMs?: number;
    queueCap?: number;
  }) {
    const clock = makeClock();
    const { logger, events } = makeLogger();
    const sends: PendingSubmission[] = [];
    const accepted: Array<{ item: PendingSubmission; stored: boolean }> = [];
    let i = 0;
    const queue = new SubmissionRetryQueue({
      logger,
      send: async (pending) => {
        sends.push(pending);
        // The LAST outcome repeats, so a test that wants "fails forever" supplies one entry.
        const out = opts.outcomes[Math.min(i, opts.outcomes.length - 1)];
        i += 1;
        return out;
      },
      onAccepted: (pending, stored) => { accepted.push({ item: pending, stored }); },
      now: clock.now,
      schedule: (fn, ms) => clock.schedule(fn, ms),
      ...(opts.maxAttempts === undefined ? {} : { maxAttempts: opts.maxAttempts }),
      ...(opts.retryWindowMs === undefined ? {} : { retryWindowMs: opts.retryWindowMs }),
      ...(opts.queueCap === undefined ? {} : { queueCap: opts.queueCap }),
    });
    return { queue, clock, events, sends, accepted };
  }

  it("CLAUSE 1 — a send that reached nobody is retried when signaling reconnects, and lands", async () => {
    const h = harness({ outcomes: [{ ok: true, submissionId: item().submissionId, stored: true }] });
    expect(h.queue.enqueue(item(), "signaling_reconnecting")).toBe(true);

    // Nothing is attempted while the stream is down: an immediate retry only spends the budget on
    // a connection that does not exist.
    await h.clock.advance(1_000);
    expect(h.sends).toHaveLength(0);

    // The SignalingManager reconnected — same node or another, this queue does not know and must
    // not care. That is the whole failover mechanism.
    h.queue.onSignalingConnected("Alice");
    await h.clock.advance(1_000);

    expect(h.sends).toHaveLength(1);
    // The SAME sealed bytes and the SAME content-derived id. Re-sealing would produce a different
    // ciphertext, and re-composing a different id — which is what would turn the retry into a
    // second endorsement.
    expect(h.sends[0].submissionId).toBe(item().submissionId);
    expect(h.sends[0].ciphertext).toBe(CIPHERTEXT);
    // ACCEPTED IS REPORTED, not merely logged: the local handle is written exactly as it is on a
    // first-pass send, or a later withdrawal has nothing to name.
    expect(h.accepted).toEqual([{ item: h.sends[0], stored: true }]);
    expect(h.queue.list("agent-alice")).toEqual([]);
  });

  it("CLAUSE 1 — a reconnect for ANOTHER agent does not fire this agent's retry", async () => {
    const h = harness({ outcomes: [{ ok: true, submissionId: item().submissionId, stored: true }] });
    h.queue.enqueue(item(), "signaling_lost");
    h.queue.onSignalingConnected("Bob");
    await h.clock.advance(1_000);
    expect(h.sends).toHaveLength(0);
  });

  it("CLAUSE 5 — while retrying, the surface names the state, the reason and the next step", async () => {
    const h = harness({ outcomes: [fail("directory_unreachable")] });
    h.queue.enqueue(item(), "signaling_reconnecting");

    const listed = h.queue.list("agent-alice");
    expect(listed).toHaveLength(1);
    expect(listed[0].submissionId).toBe(item().submissionId);
    expect(listed[0].op).toBe("submit");
    expect(listed[0].delivery.state).toBe("retrying");
    // NAME THE VALUE, not its shadow. "It is not accepted" would pass for a queue that had lost
    // the row; the operator needs the cause that put it here and what happens next.
    expect(listed[0].delivery.lastReason).toBe("signaling_reconnecting");
    expect(listed[0].delivery.guidance).toContain("retrying");
  });

  it("CLAUSE 4 — a failure that REACHED a node spends the budget and gives up as attempts_exhausted", async () => {
    const h = harness({ outcomes: [fail("submission_write_timeout")], maxAttempts: 3 });
    h.queue.enqueue(item(), "submission_write_timeout");
    h.queue.onSignalingConnected("Alice");
    // Well past the whole backoff ladder for three attempts.
    await h.clock.advance(60 * 60_000);

    expect(h.sends).toHaveLength(3);
    const listed = h.queue.list("agent-alice");
    expect(listed).toHaveLength(1);
    expect(listed[0].delivery.state).toBe("gave_up");
    expect(listed[0].delivery.gaveUpBecause).toBe("attempts_exhausted");
    expect(listed[0].delivery.lastReason).toBe("submission_write_timeout");
    // A TERMINAL STATE WITH A NEXT STEP, not a bare code. The operator can act on this one.
    expect(listed[0].delivery.guidance).toMatch(/cello_attestations_issue/);
    const gaveUp = h.events.filter((e) => e.event === "signal.submission.retry.gave_up");
    expect(gaveUp).toHaveLength(1);
    expect(gaveUp[0].ctx["stoppedBecause"]).toBe("attempts_exhausted");
  });

  it("CLAUSE 4 — a transport failure does NOT spend the budget; the WINDOW bounds it", async () => {
    // The stream turns over roughly every 70 seconds in production, so a flapping connection would
    // burn a five-attempt budget in six minutes and durably give up on a submission whose only
    // problem was that the network was moving. `directory_unreachable` says nothing about the
    // SUBMISSION — it is our own precondition — so it is bounded by wall clock instead.
    const h = harness({ outcomes: [fail("directory_unreachable")], maxAttempts: 3, retryWindowMs: 10 * 60_000 });
    h.queue.enqueue(item(), "signaling_lost");

    for (let i = 0; i < 8; i++) {
      h.queue.onSignalingConnected("Alice");
      await h.clock.advance(2 * 60_000);
    }
    // More attempts than the budget, precisely because none of them was a verdict on the session.
    expect(h.sends.length).toBeGreaterThan(3);

    const listed = h.queue.list("agent-alice");
    expect(listed[0].delivery.state).toBe("gave_up");
    expect(listed[0].delivery.gaveUpBecause).toBe("retry_window_elapsed");
    expect(listed[0].delivery.guidance).toMatch(/cello_attestations_issue/);
  });

  it("CLAUSE 4 — in a MIXED run, only the failures that reached a node are counted", async () => {
    /**
     * THE COUNTER ITSELF, pinned separately from the give-up branch, because a mutation that made
     * a local precondition increment `attempts` SURVIVED the two tests above: the exhaustion branch
     * is guarded on `!localPrecondition`, so the wrong count was invisible there. It is visible
     * HERE — `delivery.attempts` is a number the operator reads, and it is the backoff's input.
     *
     * The sequence alternates deliberately. Three of these six sends are transport failures that
     * say nothing about the submission; three reached a node and did not answer. With a budget of 3
     * the run must end on the THIRD timeout, having counted exactly three.
     */
    const outcomes: SendSubmissionResult[] = [
      fail("signaling_reconnecting"),
      fail("submission_write_timeout"),
      fail("directory_unreachable"),
      fail("submission_write_timeout"),
      fail("signaling_lost"),
      fail("submission_write_timeout"),
    ];
    const h = harness({ outcomes, maxAttempts: 3, retryWindowMs: 24 * 60 * 60_000 });
    h.queue.enqueue(item(), "signaling_reconnecting");
    h.queue.onSignalingConnected("Alice");
    await h.clock.advance(60 * 60_000);

    expect(h.sends).toHaveLength(6);
    const listed = h.queue.list("agent-alice");
    expect(listed[0].delivery.state).toBe("gave_up");
    expect(listed[0].delivery.gaveUpBecause).toBe("attempts_exhausted");
    // THE VALUE, not its shadow: six sends, three of which were verdicts about nothing.
    expect(listed[0].delivery.attempts).toBe(3);
  });

  it("CLAUSE 4 — a bounded queue refuses to grow without limit, and says so", () => {
    const h = harness({ outcomes: [fail("directory_unreachable")], queueCap: 2 });
    expect(h.queue.enqueue(item({ submissionId: "11".repeat(32) }), "signaling_lost")).toBe(true);
    expect(h.queue.enqueue(item({ submissionId: "22".repeat(32) }), "signaling_lost")).toBe(true);
    // REFUSED, not silently dropped — the caller reports the plain failure so the operator knows
    // this one is theirs to re-run.
    expect(h.queue.enqueue(item({ submissionId: "33".repeat(32) }), "signaling_lost")).toBe(false);
    expect(h.events.some((e) => e.event === "signal.submission.retry.queue_full")).toBe(true);
  });

  it("is SERIAL — two queued submissions never have two sends in flight at once", async () => {
    const clock = makeClock();
    const { logger } = makeLogger();
    let inFlight = 0;
    let maxInFlight = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const queue = new SubmissionRetryQueue({
      logger,
      send: async () => {
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await gate;
        inFlight -= 1;
        return fail("directory_unreachable");
      },
      onAccepted: () => {},
      now: clock.now,
      schedule: (fn, ms) => clock.schedule(fn, ms),
    });
    queue.enqueue(item({ submissionId: "11".repeat(32) }), "signaling_lost");
    queue.enqueue(item({ submissionId: "22".repeat(32) }), "signaling_lost");
    queue.onSignalingConnected("Alice");
    await clock.advance(1_000);
    expect(maxInFlight).toBe(1);
    release();
    await clock.advance(1_000);
  });

  it("stop() leaves nothing armed — a background retry must not hold a shutdown open", async () => {
    const h = harness({ outcomes: [fail("directory_unreachable")] });
    h.queue.enqueue(item(), "signaling_lost");
    h.queue.onSignalingConnected("Alice");
    await h.clock.advance(1_000);
    const before = h.sends.length;
    h.queue.stop();
    // ASSERT THE TIMER, not merely the absence of a send. Reverting only `#timer?.cancel()` left
    // this green before, because `#pump`'s own `#stopped` check suppressed the send — so the test
    // named "nothing is armed" was really asserting "nothing is sent". A dead timer left behind is
    // its own defect: it shows up in a shutdown trace and keeps the process alive.
    expect(h.clock.pendingCount(), "stop() left a timer armed").toBe(0);
    await h.clock.advance(60 * 60_000);
    expect(h.sends).toHaveLength(before);
  });

  it("stop() NAMES every submission it drops — a restart must not lose them silently", async () => {
    /**
     * The operator was told "you do NOT need to run this again". A restart takes the queue with it,
     * and before this there was no durable trace anywhere naming what was lost — not in `issued`
     * (nothing reached a node), not in `in_flight` (the process is gone), and not in the log.
     */
    const h = harness({ outcomes: [fail("directory_unreachable")] });
    h.queue.enqueue(item({ submissionId: "11".repeat(32) }), "signaling_lost");
    h.queue.enqueue(item({ submissionId: "22".repeat(32), subject: "ee".repeat(32) }), "signaling_lost");
    h.queue.stop();

    const dropped = h.events.filter((e) => e.event === "signal.submission.retry.dropped_on_shutdown");
    expect(dropped).toHaveLength(2);
    // NAME THE VALUE: the id alone cannot be turned back into a submission, because the body is
    // deliberately not stored. The subject is what tells the operator WHO they were vouching for.
    expect(dropped.map((e) => e.ctx["subject"]).sort()).toEqual(["bb".repeat(32), "ee".repeat(32)]);
    expect(dropped[0].ctx["impact"]).toMatch(/issued again/);
  });

  it("a submission a node ACCEPTS during shutdown still records its handle", async () => {
    /**
     * `stop()` does not await the send in flight. When the node accepts it afterwards the
     * endorsement is REAL and the portal will mint it — so a daemon that recorded nothing would
     * leave the operator holding no handle, and a submission with no handle can never be withdrawn.
     */
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const clock = makeClock();
    const { logger, events } = makeLogger();
    const accepted: Array<{ item: PendingSubmission; stored: boolean }> = [];
    const queue = new SubmissionRetryQueue({
      logger,
      send: async (pending) => {
        await gate;
        return { ok: true, submissionId: pending.submissionId, stored: true };
      },
      onAccepted: (pending, stored) => { accepted.push({ item: pending, stored }); },
      now: clock.now,
      schedule: (fn, ms) => clock.schedule(fn, ms),
    });
    queue.enqueue(item(), "signaling_lost");
    queue.onSignalingConnected("Alice");
    await clock.advance(1_000);

    // The daemon is stopping while the node is still deciding.
    queue.stop();
    release();
    for (let i = 0; i < 40; i++) await Promise.resolve();

    expect(accepted, "an endorsement a node accepted left no local handle").toHaveLength(1);
    const acceptedEvents = events.filter((e) => e.event === "signal.submission.retry.accepted");
    expect(acceptedEvents).toHaveLength(1);
    // The log line alone must be enough to reconstruct the handle, because the database may already
    // be closed by the time this runs.
    expect(acceptedEvents[0].ctx["subject"]).toBe("bb".repeat(32));
    expect(acceptedEvents[0].ctx["duringShutdown"]).toBe(true);
  });
});
