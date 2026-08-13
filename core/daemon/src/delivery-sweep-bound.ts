/**
 * DOD-MP-SWEEP-ALIVE-1 — bound one agent's delivery pass so a hang cannot end delivery.
 *
 * ── WHY THIS EXISTS ───────────────────────────────────────────────────────────────────────────
 *
 * The daemon's sweep is guarded against overlap by a boolean released in the `finally` of an async
 * body. That release runs only when the body SETTLES. A throw is covered — there is a `catch` and
 * the `finally` still runs. **An await that never settles is not covered at all.**
 *
 * So one hung pass wedges the guard for the life of the process: the interval keeps firing, hits
 * `if (running) return`, and emits nothing. No log line, no error, no counter — while every
 * document edit sits undelivered and the document reports healthy on both sides.
 *
 * Observed live 2026-08-13: last completed sweep `17:06:28`; delivery work carrying a `dlv-`
 * correlation id at `17:07:38`; no sweep ever completed again. The peer daemon, same build, one
 * agent, swept on schedule throughout — so the hang is state-dependent, not a general code break.
 *
 * ── WHY IT BOUNDS THE CLASS, NOT THE INSTANCE ─────────────────────────────────────────────────
 *
 * `acquireSession` ends in `await deps.openSession(...)` with no timeout of its own, which makes it
 * the candidate. It is only a candidate: nothing in the log records which await hung. Closing just
 * that one would be a guess wearing a fix's clothes, and the wedge would survive anywhere else it
 * can happen. Bounding the pass holds however the hang arises.
 *
 * The bound does NOT cancel the hung work — it cannot; a promise has no abort. It stops the SWEEP
 * from waiting on it, so the remaining agents are swept and the next tick proceeds. A wedged agent
 * degrades alone and loudly, which is the fan-out-availability doctrine applied to the sweep
 * itself: one unreachable participant must never take the others down with it.
 *
 * ── THE BOUND ALONE IS NOT ENOUGH ─────────────────────────────────────────────────────────────
 *
 * `DocumentDelivery.tick` carries the IDENTICAL defect one layer down: it caches its pass in
 * `#inFlight` and clears it in a `finally`. So after a hang, every later tick for that agent
 * returns the SAME already-hung promise — the agent never delivers again, and each pass re-races it
 * for the full bound, which doubles the sweep interval for every healthy agent on the daemon.
 * Bounding without evicting therefore trades a silent outage for a slower one. `sweepAgentEvicting`
 * below drops the wedged worker so the next tick constructs a fresh one and re-enters the pass.
 *
 * Evicting cannot double-send: the pass claims each row (`recordHolderAttempt`) BEFORE it dials, so
 * anything the hung pass was holding is already scheduled into the future and is not due.
 *
 * ── ONE LOAD-BEARING CONSTRAINT, STATED WHERE IT BINDS ────────────────────────────────────────
 *
 * `setTimeout` inside a `Promise.race` is safe here ONLY because the daemon's `stop()` does not
 * await the in-flight sweep. If anyone restores that await, a race whose timer never fires during a
 * draining loop can hang shutdown — see the shutdown note in daemon.ts.
 */

export interface BoundedPassDeps {
  logger: { warn(event: string, ctx: Record<string, unknown>): void };
  /** How long one agent's pass may run before it is declared stuck. */
  timeoutMs: number;
  /** Named in the log line — an operator needs to know WHICH agent stopped delivering. */
  agentName: string;
}

export type BoundedPassResult<T> = { completed: true; value: T } | { completed: false };

export async function runAgentPassBounded<T>(
  deps: BoundedPassDeps,
  run: () => Promise<T>,
): Promise<BoundedPassResult<T>> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  /** Set the moment the bound wins — the only state that makes a later rejection 'late'. */
  let abandoned = false;
  const bound = new Promise<{ completed: false }>((resolve) => {
    timer = setTimeout(() => {
      abandoned = true;
      deps.logger.warn("document.delivery.pass.stuck", {
        agentName: deps.agentName,
        timeoutMs: deps.timeoutMs,
        // ACCURATE ABOUT RECOVERY. This said "until it clears", and it did not clear: the worker
        // cached the hung pass and handed it back forever. It is true only because the caller now
        // evicts the worker, so say what actually happens next rather than implying patience.
        impact:
          "this agent's delivery pass did not finish, so the sweep stopped waiting for it and " +
          "dropped the worker — a fresh pass starts on the next tick. Repeats mean the dial " +
          "underneath is hanging, not that the pass is merely slow",
      });
      resolve({ completed: false });
    }, deps.timeoutMs);
    // Never hold the process open on account of the bound itself.
    timer.unref?.();
  });

  try {
    // A THROW PROPAGATES. Containment lives in the caller, which already logs
    // `document.delivery.tick.failed` and releases its guard; swallowing it here would silently
    // delete that reporting and make a failing pass indistinguishable from a healthy one.
    const attempt = run();
    // THE LOSING BRANCH IS STILL WATCHED. If a pass the sweep GAVE UP ON eventually rejects, the
    // settled race absorbs it and the error is logged nowhere — discarding the single best piece of
    // evidence about WHICH await hung, on a defect whose root cause is explicitly not established.
    //
    // ONLY WHEN IT IS ACTUALLY LATE. A pass that throws while the race is still pending propagates
    // to the caller, which logs it; reporting that here too would double-report an ordinary failure
    // and blunt the one event that means something unusual happened.
    attempt.catch((err: unknown) => {
      if (!abandoned) return;
      deps.logger.warn("document.delivery.pass.late_failure", {
        agentName: deps.agentName,
        reason: err instanceof Error ? err.message : String(err),
        impact: "a pass the sweep had already given up on failed afterwards",
      });
    });
    return await Promise.race([attempt.then((value) => ({ completed: true as const, value })), bound]);
  } finally {
    // Cleared on EVERY exit, including the throw. Left armed, each pass would pin a timer per agent
    // per tick for the life of a process whose whole purpose is to keep running.
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * One agent's pass, bounded AND evicted on a wedge.
 *
 * Separated from `runAgentPassBounded` because eviction needs the worker registry, and separated
 * from the daemon because the daemon's sweep cannot be constructed in a test — which is exactly why
 * the call site went uncovered while the helper beneath it was well tested.
 */
export interface EvictingSweepDeps<T> extends BoundedPassDeps {
  /** The per-agent worker registry. The wedged entry is dropped so the next tick builds a fresh one. */
  workers: { delete(agentName: string): unknown };
  run: () => Promise<T>;
}

export async function sweepAgentEvicting<T>(
  deps: EvictingSweepDeps<T>,
): Promise<BoundedPassResult<T>> {
  const outcome = await runAgentPassBounded(deps, deps.run);
  if (!outcome.completed) {
    // WITHOUT THIS the agent is finished: its worker keeps handing back the same hung promise, so
    // it never delivers again and every future pass pays the full bound waiting for it.
    deps.workers.delete(deps.agentName);
  }
  return outcome;
}
