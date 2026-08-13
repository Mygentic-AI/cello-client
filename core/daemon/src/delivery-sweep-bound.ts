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
  const bound = new Promise<{ completed: false }>((resolve) => {
    timer = setTimeout(() => {
      deps.logger.warn("document.delivery.pass.stuck", {
        agentName: deps.agentName,
        timeoutMs: deps.timeoutMs,
        impact:
          "this agent's delivery pass did not finish and the sweep stopped waiting for it — " +
          "its documents are not being delivered until it clears",
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
    return await Promise.race([run().then((value) => ({ completed: true as const, value })), bound]);
  } finally {
    // Cleared on EVERY exit, including the throw. Left armed, each pass would pin a timer per agent
    // per tick for the life of a process whose whole purpose is to keep running.
    if (timer !== undefined) clearTimeout(timer);
  }
}
