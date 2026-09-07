/**
 * ONE of the daemon's two background sweeps — the revival-bound sweep — and the timer that re-arms
 * it. The other, the document reconcile sweep, is still in the composition root beside the document
 * wiring it drives.
 *
 * A sweep is not a one-off: a session interrupted at 09:00 on a daemon that stays up all week would
 * otherwise be swept only at the next boot, and a long-lived daemon is the normal case. The timer
 * `unref`s so a pending tick never holds the process open.
 *
 * The timer is returned rather than started-and-forgotten because shutdown has to clear it, and a
 * timer nobody holds a handle to is a process that will not exit.
 */
import type { Logger } from "./types.js";
import { REVIVAL_WINDOW_MS, REVIVAL_BOUND_SWEEP_MS, type SessionNodeManager } from "./session-node-manager.js";

export interface BootSweepsDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
}

export function startBootSweeps(deps: BootSweepsDeps) {
  const { logger, sessionNodeManager } = deps;

  /**
   * DOD-M12B-REVIVAL-BOUND-1 — close the interrupted sessions the revival window has expired.
   *
   * Runs at boot beside the restart-seal resolver, and is its complement: the resolver takes the
   * sessions we can describe truthfully (`interrupted_by = 'local'`) and gets them a receipt; this
   * takes everything else and shuts the door without asserting a cause.
   *
   * It must run even though nothing has revived a session yet — the reason is Andre's 2026-08-18
   * tenet, *"leave nothing open that is no longer needed."* `ingestReceivedContent` accepts content
   * into an `interrupted` session by design, so a session that can never be revived is a write
   * surface a reprogrammed peer can use for as long as the row exists. Boot is where the store is
   * swept for exactly that.
   *
   * NOT AWAITED, and caught: this is a best-effort sweep over rows that have already waited a day.
   * Blocking the daemon's startup on a directory-free DB walk buys nothing, and a throw here would
   * take down a daemon that is otherwise healthy.
   */
  const runRevivalBoundSweep = (): void => {
    void sessionNodeManager
      .closeExpiredUnrevivableSessions(Date.now(), REVIVAL_WINDOW_MS)
      .catch((err: unknown) => {
        logger.warn("session.revival_bound.sweep.failed", {
          error: err instanceof Error ? err.message : String(err),
          impact: "expired sessions were not closed this pass and still accept content",
        });
      });
  };
  runRevivalBoundSweep();

  /**
   * RE-ARMED, because boot alone is not a bound.
   *
   * A session interrupted at 09:00 on a daemon that stays up all week would otherwise be writable
   * for the whole week — and a long-lived daemon is the normal case, not the exception. Boot-only
   * would have made the control fire exactly when it is least needed (a machine that restarts often
   * is a machine whose sessions get swept often) and never when it is most needed.
   *
   * Hourly against a 24-hour window: the overshoot is at most an hour on a bound measured in days,
   * and the pass is a single indexed DB walk with no network in it. `unref` so a pending timer
   * never holds the process open, matching `reconcileSweepTimer` beside it.
   */
  const revivalBoundSweepTimer = setInterval(runRevivalBoundSweep, REVIVAL_BOUND_SWEEP_MS);
  revivalBoundSweepTimer.unref?.();

  // The sweep function itself is not returned — its only callers are here (once at construction,
  // then on the timer). Only the timer escapes, because shutdown has to clear it.
  return { revivalBoundSweepTimer };
}
