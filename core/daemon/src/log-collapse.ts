import type { Logger } from "./types.js";

/**
 * DOD-M15-LOGBOUND-1 part A — write a repeating log line ONCE, then count it.
 *
 * The file that produced this order was 180 MB and 469,065 lines. 168 MB of it — 95% — was a
 * single `session.key.announce.failed` line repeated 413,590 times, byte-identical apart from its
 * timestamp, from a retry that never gave up.
 *
 * **The disk was the smaller half.** That loop hid behind its own output for eleven hours. A file
 * that is 95% one sentence is not a diagnostic surface; it is a haystack the daemon builds around
 * its own needle, faster than anyone can read it.
 *
 * **This is the rule `045-REFUSALSTORM` applies to the operator's inbox, one layer down.** Same
 * idea in two places, not two mechanisms.
 *
 * ⚠️ **This makes a storm cheap. It does not make a storm correct.** The loops themselves are
 * fixed by `045-REFUSALSTORM` and `DOD-M15-KEYANNOUNCE-LOOP-1`; this unit must not be cited as
 * covering either.
 *
 * ## The gate is a RATE, not a count — and the first build got this wrong
 *
 * The obvious design suppresses everything after the first occurrence and re-reports at the 10th,
 * 100th, 1,000th. It was built that way, and review found two defects in it that matter more than
 * the bytes it saved:
 *
 * 1. **A bounded retry that failed three times printed one line.** Three is not a power of ten, so
 *    attempts two and three were dropped and nothing anywhere ever said they happened. An operator
 *    whose standing receiver cannot bind then reads one `session.node.create.failed` followed by
 *    `session.standing_receiver.dead`, and cannot tell a retry that ran from a retry that never
 *    fired — which is the first thing they would go and check.
 * 2. **A chronic failure went permanently silent.** A run never expired, so something failing once
 *    an hour reached its 10th occurrence on day one and was next written on day four. The daemon
 *    stopped reporting an ongoing failure precisely because it had been failing for a long time.
 *
 * So nothing is suppressed until a key is genuinely FLOODING: more than {@link STORM_BURST}
 * occurrences inside {@link STORM_WINDOW_MS}. Below that rate every line is written exactly as it
 * was before this unit existed. The measured storm ran at 4–17 lines/second and trips the gate on
 * its 21st line; an ordinary two-to-nine repeat never trips it at all, and neither does a slow
 * chronic failure — which is how both defects above stay fixed rather than traded against each
 * other.
 */

/** Occurrences of one key inside one window that mean "this is a flood, not a repeat". */
export const STORM_BURST = 20;

/** The window the burst is measured over. Also the idle period that ENDS a storm. */
export const STORM_WINDOW_MS = 10_000;

/**
 * Bound on the table. Without one, the thing that removes an unbounded log would itself be an
 * unbounded map — the same defect one layer further in.
 *
 * Eviction is least-recently-USED, and that is load-bearing rather than tidy. Plenty of events
 * carry a value unique to the occurrence — a fresh root hash, a content hash, a peer id — so in
 * ordinary operation the table is mostly keys that will never be seen again. Under
 * insertion-order eviction the one key the table exists to hold, the one being hit thousands of
 * times a second, is evicted on the same schedule as keys that are read once; the count resets and
 * the single number that made the storm diagnosable is destroyed. Under LRU a never-repeating key
 * is always the oldest and is always the first to go.
 */
export const LOG_COLLAPSE_MAX_KEYS = 2048;

/** Separator for key parts. A control character cannot appear in an event name or a field value. */
const SEP = String.fromCharCode(31);

interface Run {
  /** Carried so a run can be closed out by something other than its own next occurrence. */
  level: "debug" | "info" | "warn" | "error";
  event: string;
  /** Start of the current rate window. */
  windowStartMs: number;
  /** The previous occurrence, so a gap longer than a window can END a flood. */
  lastAtMs: number;
  /** Occurrences inside the current window, whether written or suppressed. */
  windowCount: number;
  /** True once the burst gate has tripped and lines are being folded. */
  suppressing: boolean;
  /** When suppression began, for the elapsed window on each milestone. */
  suppressStartMs: number;
  /** Occurrences folded since suppression began. */
  suppressedCount: number;
  /**
   * The most recent payload, so a milestone and the closing summary carry current context.
   *
   * Written ONLY while suppressing. Holding a reference to every caller's context object for the
   * life of the process would pin up to 2,048 payloads, some carrying error objects with stacks,
   * to keep a field that only a closing line ever reads.
   */
  lastCtx: Record<string, unknown>;
}

/**
 * The collapse key.
 *
 * ⚠️ **IT MUST NOT BE LOOSER THAN event + session + reason**, and it is exactly that. Keying on the
 * event name alone would merge a hundred sessions failing once each into one line reading "x100" —
 * strictly worse than the noise this removes, because a fan-out is the shape you most need to see
 * and it would be reported as a repeat. The level is in the key too: the same event at `warn` and
 * at `error` is two facts.
 *
 * **And it is deliberately NOT the whole payload**, which is the second thing the first build got
 * wrong. Keying on every field looked tighter and therefore safer, and it is neither:
 *
 * - `session.key.announce.failed` — the very event this unit was written for — carries an `attempt`
 *   counter. Every attempt is a different payload, so a full-payload key collapses NOTHING on the
 *   one path that produced 168 MB. The historical storm only collapsed because the pre-fix bug
 *   pinned `attempt` at 1; the fix that made the retry chain correct is what would have defeated it.
 * - A loop minting a fresh key per iteration also churns the whole table at the rate it runs,
 *   evicting every other run in it.
 *
 * The cost of the looser key is paid elsewhere rather than ignored: because suppression is gated on
 * a RATE, a payload field that changes between occurrences is written in full at any ordinary rate,
 * and is only folded once the key is genuinely flooding — at which point a count and a rate are
 * more use than ten thousand individual values. Milestones republish the most recent payload, so
 * the newest values stay on the record.
 *
 * Returns `null` when the key cannot be built from what the call site passed. **Such a line does
 * not collapse at all** — losing the saving is correct where losing the distinction is not.
 */
function collapseKey(level: string, event: string, ctx: Record<string, unknown>): string | null {
  const sessionId = ctx["sessionId"];
  const reason = ctx["reason"];
  if (typeof sessionId !== "string" && typeof reason !== "string") return null;
  return [level, event, String(sessionId ?? ""), String(reason ?? "")].join(SEP);
}

/** First occurrence, then the 10th, 100th, 1,000th — a power of ten. */
function isMilestone(count: number): boolean {
  if (count === 1) return true;
  let n = count;
  while (n % 10 === 0) n /= 10;
  return n === 1;
}

/**
 * Wrap a logger so a FLOODING line is written once and then counted.
 *
 * Wrapping the composition root covers every call site at once, which is what makes this a
 * property of the daemon's logging rather than a discipline each call site has to remember.
 */
export function createCollapsingLogger(sink: Logger, now: () => number = Date.now): Logger {
  const runs = new Map<string, Run>();

  /**
   * Report a fold that has ended: how many lines it swallowed, and over how long.
   *
   * ⚠️ **THE WINDOW IS MEASURED TO THE LAST OCCURRENCE, NOT TO NOW**, and getting that wrong made
   * this line state the opposite of what happened. A flood of 479 lines over 25 seconds — 19 a
   * second — was reported as `repeatWindowMs: 21623950`, six hours, because the idle gap that
   * proved the flood was over had already been folded into the elapsed time. An operator dividing
   * those two numbers reads 1.3 an hour: a trickle, when it was the storm.
   */
  function closeRun(run: Run): void {
    sink[run.level](run.event, {
      ...run.lastCtx,
      repeatedCount: run.suppressedCount,
      repeatWindowMs: Math.max(0, run.lastAtMs - run.suppressStartMs),
      repeatEnded: true,
    });
    run.suppressing = false;
    run.suppressedCount = 0;
  }

  /**
   * One amortised look at the oldest run per line written.
   *
   * Without it a fold that simply STOPS is never reported: the closing line is emitted by the
   * key's own next occurrence, and a storm whose cause is fixed — or whose daemon is shut down —
   * has no next occurrence. The measured 413,590-line storm would have ended on
   * `repeatedCount: 100000`, understating itself fourfold, with nothing saying it had finished.
   */
  function sweepOldest(at: number, currentKey: string): void {
    const oldest = runs.entries().next();
    if (oldest.done) return;
    const [key, run] = oldest.value;
    if (key === currentKey) return;
    if (at - run.lastAtMs < STORM_WINDOW_MS) return;
    if (run.suppressing) closeRun(run);
    runs.delete(key);
  }

  function emit(level: "debug" | "info" | "warn" | "error", event: string, ctx: Record<string, unknown>): void {
    const key = collapseKey(level, event, ctx);
    if (key === null) {
      sink[level](event, ctx);
      return;
    }

    const at = now();
    sweepOldest(at, key);

    const existing = runs.get(key);
    if (existing === undefined) {
      if (runs.size >= LOG_COLLAPSE_MAX_KEYS) {
        const oldest = runs.entries().next();
        if (!oldest.done) {
          // Evicting a run mid-fold would take its total with it and restart the next occurrence
          // from one. Over-reporting is the safe direction; losing the count is not.
          if (oldest.value[1].suppressing) closeRun(oldest.value[1]);
          runs.delete(oldest.value[0]);
        }
      }
      runs.set(key, {
        level, event, windowStartMs: at, lastAtMs: at, windowCount: 1,
        suppressing: false, suppressStartMs: 0, suppressedCount: 0, lastCtx: ctx,
      });
      sink[level](event, ctx);
      return;
    }

    // Least-recently-USED: re-inserting moves this key to the young end of the eviction order.
    runs.delete(key);
    runs.set(key, existing);

    /**
     * A gap longer than a window means the flood has stopped — measured from the PREVIOUS
     * occurrence, never from the window's own tally. Reading the tally was the first version of
     * this and it could never end a storm: during one, the count carried over from the last
     * window is high by definition, so the "has it died down" test was never true.
     */
    const idle = at - existing.lastAtMs >= STORM_WINDOW_MS;

    if (idle) {
      if (existing.suppressing) closeRun(existing);
      existing.windowStartMs = at;
      existing.windowCount = 0;
    } else if (at - existing.windowStartMs >= STORM_WINDOW_MS) {
      /**
       * ⚠️ A FULL WINDOW PASSED WITH TRAFFIC — so re-test the RATE, do not just roll the window.
       * Without this, `suppressing` latches: the only exit is a ten-second silence, so a retry
       * that starts fast and backs off to anything under one line per ten seconds stays folded
       * forever. Measured on the built module: 30 lines in 3 seconds trips the gate, and the next
       * 1,200 occurrences spread over three hours produce three lines. That is the chronic-failure
       * silence this redesign was written to remove, re-entered through a different door.
       */
      if (existing.suppressing && existing.windowCount <= STORM_BURST) closeRun(existing);
      existing.windowStartMs = at;
      existing.windowCount = 0;
    }

    existing.lastAtMs = at;
    existing.windowCount += 1;

    if (existing.suppressing) {
      existing.lastCtx = ctx;
      existing.suppressedCount += 1;
      // The 1st suppressed occurrence is not a milestone worth printing — the line that tripped
      // the gate, immediately above it, already said the fold had started.
      if (existing.suppressedCount === 1 || !isMilestone(existing.suppressedCount)) return;
      sink[level](event, {
        ...ctx,
        repeatedCount: existing.suppressedCount,
        repeatWindowMs: Math.max(0, at - existing.suppressStartMs),
      });
      return;
    }

    if (existing.windowCount > STORM_BURST) {
      // The gate trips. This line is still written in full, and says that the ones behind it
      // will not be — an operator should never have to infer that lines are being dropped.
      existing.suppressing = true;
      existing.suppressStartMs = at;
      existing.suppressedCount = 0;
      existing.lastCtx = ctx;
      sink[level](event, { ...ctx, repeatsCollapsing: true, repeatRatePerWindow: existing.windowCount });
      return;
    }

    sink[level](event, ctx);
  }

  return {
    debug: (event, ctx) => { emit("debug", event, ctx); },
    info: (event, ctx) => { emit("info", event, ctx); },
    warn: (event, ctx) => { emit("warn", event, ctx); },
    error: (event, ctx) => { emit("error", event, ctx); },
  };
}
