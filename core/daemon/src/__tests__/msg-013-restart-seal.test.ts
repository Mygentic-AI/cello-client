/**
 * DOD-M12B-RESTART-SEAL-1 — a session our own stop interrupted must resolve itself, with a receipt.
 *
 * MEASURED 2026-08-17 over seventeen days of one operator's daemon log. Of 118 sessions flipped to
 * `interrupted`, **114 landed immediately after `daemon.stopped`** — the graceful-shutdown sweep
 * closing every open session on the way out — and 2 came from the operator's own offline switch.
 * **Zero** came from a relay frame, a relay stream close, or the boot sweep. Not one session in
 * seventeen days was interrupted by a laptop close, a wifi hop, or a counterparty hanging up.
 *
 * Those sessions cannot be resumed: their transport keypairs died with the process. Their only exit
 * today is `cello_close_session {force:true}`, which the code itself calls an escape hatch and which
 * forfeits the notarized receipt — **137 sessions carrying 3,576 messages produced nothing.**
 *
 * So the choice is not *seal or resume*, it is *seal or abandon*, and Andre ruled it 2026-08-17:
 * "do not resume. Resolve… make it a seal, not a force-close."
 *
 * WHAT MUST NOT BREAK — SI-001. `close-session-handler.ts` opens with a standing decision:
 * *"there is NO auto-seal on a session_interrupted receipt… a daemon that sealed on its own would
 * notarize a conversation nobody chose to end."* That is about a LIVE interruption, where the
 * operator is at the keyboard and may still want to wait. It keeps holding. This resolver keys on
 * `interrupted_by = 'local'` and touches nothing else.
 *
 * Revert test: make the resolver ignore `retryAfterSeconds` and use a fixed backoff, and the
 * reschedule case fails — the retry lands at the wrong time and the operator is back to being told
 * to come back in eleven minutes.
 */
import { describe, it, expect } from "vitest";
import { RestartSealResolver, type RestartOrphan, type SealOutcome } from "../restart-seal-resolver.js";
import type { Logger } from "../types.js";

interface LogEvent { event: string; ctx: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const push = (event: string, ctx?: Record<string, unknown>): void => { events.push({ event, ctx: ctx ?? {} }); };
  return { logger: { debug: push, info: push, warn: push, error: push }, events };
}

/** A hand-cranked clock + scheduler. Nothing runs until `advance` reaches its deadline, so every
 *  assertion below is about WHEN the resolver chose to act, not about how fast a timer happened
 *  to fire. */
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
    /** Move time forward, firing everything due, in deadline order. */
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
        // Drain the microtask chain the fired task started (the seal is async, and its continuation
        // is what schedules the next pass). This is plumbing, not leniency — every assertion below
        // is still about which calls happened and when.
        for (let i = 0; i < 20; i++) await Promise.resolve();
      }
      now = target;
    },
    pendingCount: () => pending.size,
  };
}

const ORPHAN = (sessionId: string, agentName = "alice"): RestartOrphan => ({
  // DOD-M12B-PENDING-RESOLVE-1 added `status`: the resolver now serves two populations, and a
  // give-up must not tell a pending session it is "interrupted" or point it at force-abandon.
  // These cases are all the restart-orphan population, so `interrupted` is the right default here.
  agentName, sessionId, messageCount: 4, status: "interrupted",
});

function makeResolver(opts: {
  orphans: RestartOrphan[];
  seal: (agentName: string, sessionId: string) => Promise<SealOutcome>;
  maxAttemptsPerSession?: number;
  staggerMs?: number;
  initialDelayMs?: number;
  attemptTimeoutMs?: number;
}) {
  const { logger, events } = makeLogger();
  const clock = makeClock();
  const attempts: string[] = [];
  const gaveUp: Array<{ agentName: string; sessionId: string; reason: string }> = [];
  const resolver = new RestartSealResolver({
    logger,
    markGaveUp: (agentName, sessionId, reason) => { gaveUp.push({ agentName, sessionId, reason }); },
    listRestartOrphans: () => opts.orphans,
    sealSession: async (agentName, sessionId) => {
      attempts.push(`${agentName}:${sessionId}`);
      return opts.seal(agentName, sessionId);
    },
    now: clock.now,
    schedule: clock.schedule,
    // Tests drive the boot delay explicitly; the default is asserted in its own case below.
    initialDelayMs: opts.initialDelayMs ?? 0,
    ...(opts.staggerMs !== undefined ? { staggerMs: opts.staggerMs } : {}),
    ...(opts.maxAttemptsPerSession !== undefined ? { maxAttemptsPerSession: opts.maxAttemptsPerSession } : {}),
    ...(opts.attemptTimeoutMs !== undefined ? { attemptTimeoutMs: opts.attemptTimeoutMs } : {}),
  });
  return { resolver, clock, attempts, events, gaveUp, named: (e: string) => events.filter((x) => x.event === e) };
}

const OK: SealOutcome = { ok: true };

describe("DOD-M12B-RESTART-SEAL-1: a restart-orphaned session seals itself", () => {
  it("seals the sessions our own stop left behind, instead of leaving them for a force-abandon", async () => {
    // The measured case: the operator restarts, the shutdown sweep flips everything open to
    // `interrupted`, and today they sit there until someone force-abandons them and the receipt dies.
    const h = makeResolver({ orphans: [ORPHAN("aa"), ORPHAN("bb")], seal: async () => OK });
    h.resolver.start();
    await h.clock.advance(60_000);

    expect(h.attempts, "every session the restart orphaned must be sealed").toEqual(["alice:aa", "alice:bb"]);
    expect(h.named("session.restart_seal.resolved").length).toBe(2);
  });

  it("a refused-too-early seal is RESCHEDULED at the deadline the directory named, not abandoned", async () => {
    // THE POINT OF THE UNIT. The directory answers `seal_unilateral_too_early` and hands back the
    // exact remaining grace; today that number is formatted into a sentence telling a human to come
    // back in eleven minutes, and nothing schedules anything.
    let calls = 0;
    const h = makeResolver({
      orphans: [ORPHAN("aa")],
      seal: async () => (++calls === 1 ? { ok: false, reason: "seal_counterparty_pending", retryAfterSeconds: 600 } : OK),
    });
    h.resolver.start();
    await h.clock.advance(1_000);
    expect(calls, "the first attempt happens promptly").toBe(1);

    // Not yet: 599 s is inside the window the directory named, and asking again only earns the same
    // refusal.
    // 599 s total elapsed, one second inside the 600 s window the directory named.
    await h.clock.advance(598_000);
    expect(calls, "must not batter the directory before the grace it named has elapsed").toBe(1);

    // The retry lands at the named deadline. A fixed backoff would fire at the wrong time here,
    // which is the revert test.
    await h.clock.advance(2_000);
    expect(calls, "the retry must land when the directory said it would be allowed").toBe(2);
    expect(h.named("session.restart_seal.resolved").length, "and it must actually seal").toBe(1);

    const waited = h.named("session.restart_seal.waiting");
    expect(waited.length, "the wait must be visible — an operator watching a stuck session needs to see it is scheduled").toBe(1);
    expect(waited[0]!.ctx["retryAfterSeconds"], "and it must name the deadline it is waiting on").toBe(600);
  });

  it("gives up after a bounded number of attempts, and SAYS it gave up", async () => {
    // A session whose seal can never complete must not retry forever. ABSENT IS NOT FINE: the
    // operator has to be able to see that this one needs a force-abandon, or it is invisible.
    const h = makeResolver({
      orphans: [ORPHAN("aa")],
      seal: async () => ({ ok: false, reason: "seal_unilateral_send_failed" }),
      maxAttemptsPerSession: 3,
    });
    h.resolver.start();
    await h.clock.advance(60 * 60 * 1000);

    expect(h.attempts.length, "bounded, not a forever loop").toBe(3);
    const gave = h.named("session.restart_seal.gave_up");
    expect(gave.length, "giving up silently is the same as never trying").toBe(1);
    expect(gave[0]!.ctx["attempts"]).toBe(3);
    // DURABLE, or the next boot starts the same three attempts over. A machine restarting ~6 times
    // a day would re-run a hopeless session's whole budget forever, which is the burst the stagger
    // exists to prevent, merely spread out.
    expect(h.gaveUp, "the give-up must be recorded durably, not only logged").toEqual([
      { agentName: "alice", sessionId: "aa", reason: "seal_unilateral_send_failed" },
    ]);
    expect(String(gave[0]!.ctx["guidance"]), "and it must say what the operator can still do").toMatch(/force/i);
    expect(h.clock.pendingCount(), "nothing may still be scheduled after giving up").toBe(0);
  });

  it("a refusal the COUNTERPARTY authored costs one attempt, not five — asking again is badgering", async () => {
    // Measured: `seal_interrupted_rejected_by_counterparty` fired 18 times. They declined. A
    // machine that comes back four more times over fifteen minutes is not being persistent.
    const h = makeResolver({
      orphans: [ORPHAN("aa")],
      seal: async () => ({ ok: false, reason: "seal_interrupted_rejected_by_counterparty" }),
      maxAttemptsPerSession: 5,
    });
    h.resolver.start();
    await h.clock.advance(60 * 60 * 1000);

    expect(h.attempts.length, "one attempt — a no is a no").toBe(1);
    const gave = h.named("session.restart_seal.gave_up");
    expect(gave[0]!.ctx["stoppedBecause"], "and it must say WHY it stopped, not just that it did").toBe("refusal_is_terminal");
    expect(h.gaveUp.map((g) => g.reason), "a terminal refusal is recorded durably too").toEqual(["seal_interrupted_rejected_by_counterparty"]);
  });

  it("a refusal that MIGHT clear is still retried — the terminal list must not swallow the recoverable", async () => {
    // The counterweight. `session_incomplete` means a gap, and the close's own guidance says a relay
    // pull may fill it; `seal_unilateral_timeout` (50 occurrences, the largest single blocker) is a
    // directory that did not answer in time. Marking either terminal would strand every session it
    // touches on the first try.
    for (const reason of ["session_incomplete", "seal_unilateral_timeout"]) {
      const h = makeResolver({
        orphans: [ORPHAN("aa")],
        seal: async () => ({ ok: false, reason }),
        maxAttemptsPerSession: 3,
      });
      h.resolver.start();
      await h.clock.advance(60 * 60 * 1000);
      expect(h.attempts.length, `${reason} must be retried, not given up on`).toBe(3);
    }
  });

  it("stop() halts it — a shutdown must not start new seal work, and a scheduled retry must not fire", async () => {
    // DOD-M12B-SHUTDOWN-1's rule: a shutdown that keeps starting new outbound work is not draining.
    // A seal is a directory ceremony, which is the most outbound thing this daemon does.
    let calls = 0;
    const h = makeResolver({
      orphans: [ORPHAN("aa"), ORPHAN("bb"), ORPHAN("cc")],
      seal: async () => { calls++; return { ok: false, reason: "seal_counterparty_pending", retryAfterSeconds: 10 }; },
      staggerMs: 5_000,
    });
    h.resolver.start();
    await h.clock.advance(1_000);
    expect(calls, "the first orphan is under way").toBe(1);

    h.resolver.stop();
    await h.clock.advance(60 * 60 * 1000);

    expect(calls, "no attempt may start after stop — not the stagger, not the scheduled retry").toBe(1);
    expect(h.clock.pendingCount(), "and no timer may be left holding the process open").toBe(0);
  });

  it("staggers, so twenty orphans do not fire twenty directory ceremonies at once", async () => {
    // 507 sessions accumulated on one machine. A resolver that enqueued them all in parallel would
    // turn a restart into a self-inflicted burst against the directory.
    const inFlight = { now: 0, max: 0 };
    const h = makeResolver({
      orphans: Array.from({ length: 5 }, (_, i) => ORPHAN(`s${i}`)),
      staggerMs: 5_000,
      seal: async () => {
        inFlight.now++; inFlight.max = Math.max(inFlight.max, inFlight.now);
        await Promise.resolve();
        inFlight.now--;
        return OK;
      },
    });
    h.resolver.start();
    await h.clock.advance(1_000);
    expect(h.attempts.length, "one at a time — the rest wait their turn").toBe(1);
    await h.clock.advance(30_000);
    expect(h.attempts.length).toBe(5);
    expect(inFlight.max, "never two ceremonies in flight together").toBe(1);
  });

  it("waits for the directory handshake before spending its first attempt", async () => {
    // A seal is a directory ceremony. At the instant boot finishes, signaling is still being
    // established — firing immediately would burn attempt 1 of 5 on a connection that does not
    // exist yet, and the operator would see a give-up caused by our own eagerness.
    const h = makeResolver({ orphans: [ORPHAN("aa")], seal: async () => OK, initialDelayMs: 30_000 });
    h.resolver.start();
    await h.clock.advance(29_000);
    expect(h.attempts.length, "must not attempt before the directory has had a chance to connect").toBe(0);
    await h.clock.advance(2_000);
    expect(h.attempts.length, "and must attempt once it has").toBe(1);
  });

  it("says nothing and schedules nothing when there is nothing to resolve", async () => {
    // The common case on a healthy machine. A resolver that logs or arms a timer on every clean
    // boot is noise in the one log an operator reads when something is wrong.
    const h = makeResolver({ orphans: [], seal: async () => OK });
    h.resolver.start();
    await h.clock.advance(60_000);
    expect(h.attempts.length).toBe(0);
    expect(h.events.length, "a clean boot must be silent here").toBe(0);
    expect(h.clock.pendingCount(), "and must leave no timer behind").toBe(0);
  });

  it("the PRODUCTION defaults are the documented ones — deleting one must not be silent", async () => {
    // Every other case here overrides the knobs, so the shipped values were exercised by nothing:
    // set DEFAULT_INITIAL_DELAY_MS to 0, or DEFAULT_MAX_ATTEMPTS to 1, and the whole suite stayed
    // green while production behaviour changed. This constructs the resolver with NO overrides
    // except the clock, and pins the three numbers by the behaviour they produce.
    const { logger } = makeLogger();
    const clock = makeClock();
    const attempts: number[] = [];
    const resolver = new RestartSealResolver({
      logger,
      markGaveUp: () => {},
      listRestartOrphans: () => [ORPHAN("aa"), ORPHAN("bb")],
      sealSession: async () => { attempts.push(clock.now()); return { ok: false, reason: "seal_unilateral_timeout" }; },
      now: clock.now,
      schedule: clock.schedule,
    });
    const t0 = clock.now();
    resolver.start();

    await clock.advance(29_000);
    expect(attempts.length, "DEFAULT_INITIAL_DELAY_MS must be 30 s — a seal needs the directory").toBe(0);
    await clock.advance(2_000);
    expect(attempts.length).toBe(1);
    expect(attempts[0]! - t0).toBe(30_000);

    // DEFAULT_STAGGER_MS: the second orphan follows 5 s later, not immediately.
    await clock.advance(3_000);  // t0+34 s: one second short of the 5 s stagger
    expect(attempts.length, "DEFAULT_STAGGER_MS must be 5 s — hundreds of orphans must not become hundreds of ceremonies").toBe(1);
    await clock.advance(2_000);
    expect(attempts.length).toBe(2);

    // DEFAULT_MAX_ATTEMPTS: five per session, ten across the two, then nothing more ever.
    await clock.advance(24 * 60 * 60 * 1000);
    expect(attempts.length, "DEFAULT_MAX_ATTEMPTS must be 5 per session").toBe(10);
    expect(clock.pendingCount(), "and it must leave no timer behind when it is done").toBe(0);
  });

  it("an attempt that never settles does not wedge the queue silently", async () => {
    // Without a ceiling, `#running` stays true with no timer armed and no log line: the resolver
    // stalls holding a full queue, and nothing anywhere says so.
    const h = makeResolver({
      orphans: [ORPHAN("aa")],
      seal: () => new Promise<SealOutcome>(() => { /* never settles */ }),
      maxAttemptsPerSession: 2,
    });
    h.resolver.start();
    await h.clock.advance(60 * 60 * 1000);

    const gave = h.named("session.restart_seal.gave_up");
    expect(gave.length, "a hung close must still reach a reported end").toBe(1);
    expect(gave[0]!.ctx["reason"]).toBe("restart_seal_attempt_timeout");
  });

  it("a session that seals is never retried, and start() twice does not double-enqueue", async () => {
    // Idempotence at the entry point: a second start (a reconnect hook, a retry of the startup step)
    // must not double every ceremony.
    const h = makeResolver({ orphans: [ORPHAN("aa")], seal: async () => OK });
    h.resolver.start();
    h.resolver.start();
    await h.clock.advance(60_000);
    expect(h.attempts).toEqual(["alice:aa"]);
  });
});
