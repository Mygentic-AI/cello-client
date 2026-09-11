import type { Logger } from "./types.js";

/**
 * DOD-M15-LOGBOUND-1 part A — write a repeating log line ONCE, then count it.
 *
 * The file that produced this order was 176 MB and 447,142 lines. 168 MB of it — 95% — was a
 * single `session.key.announce.failed` line repeated 413,589 times, byte-identical apart from its
 * timestamp, from a retry that never gave up.
 *
 * **The disk was the smaller half.** That loop hid behind its own output for eleven hours. A file
 * that is 95% one sentence is not a diagnostic surface; it is a haystack the daemon builds around
 * its own needle, faster than anyone can read it. So a repeat is written on its first occurrence
 * and then at order-of-magnitude milestones carrying the count and the elapsed window, and the
 * middles are dropped.
 *
 * **This is the rule `045-REFUSALSTORM` applies to the operator's inbox, one layer down.** Same
 * idea in two places, not two mechanisms.
 *
 * ⚠️ **This makes a storm cheap. It does not make a storm correct.** The loops themselves are
 * fixed by `045-REFUSALSTORM` and `DOD-M15-KEYANNOUNCE-LOOP-1`; this unit must not be cited as
 * covering either.
 */

/**
 * Bound on the collapse table. Without one, the thing that removes an unbounded log would itself
 * be an unbounded map — the same defect one layer further in.
 *
 * Eviction is oldest-first, and an evicted key's next occurrence is reported as a first
 * occurrence. Over-reporting on eviction is the safe direction; silence is not.
 */
export const LOG_COLLAPSE_MAX_KEYS = 2048;

/** Separator for key parts. A control character cannot appear in an event name or a field value. */
const SEP = "\u001f";

interface Run {
  count: number;
  firstAtMs: number;
}

/**
 * The collapse key.
 *
 * ⚠️ **IT MUST NOT BE LOOSER THAN event + session + reason.** Keying on the event name alone would
 * merge a hundred sessions failing once each into one line reading "x100" — strictly worse than the
 * noise this removes, because a fan-out is the shape you most need to see and it would be reported
 * as a repeat. The level is in the key too: the same event at `warn` and at `error` is two facts.
 *
 * **It is TIGHTER than that floor, and both halves of why are load-bearing.**
 *
 * *It includes the rest of the payload*, because "a repeat" has to mean a repeat. The storm this
 * was written for repeats byte-identically, but plenty of periodic events carry a session id and a
 * CHANGING number — `transport.connections.observed` reports a connection total on a timer. Keyed
 * on event and session alone, a total climbing 1, 2, 300 would fold into one line reading "x300",
 * and the only thing worth seeing would be the thing thrown away. Two lines that differ in a field
 * are two facts.
 *
 * *It excludes `correlationId`*, because that is the one field that is per-flow by construction
 * rather than a fact about what happened. A retry loop minting a fresh correlation id per attempt
 * is a realistic storm shape, and keying on it would mean the collapser silently stopped collapsing
 * in exactly the case it exists for. Milestones republish the most recent context, so the newest
 * correlation id stays on the record rather than being lost.
 *
 * Returns `null` when the key cannot be built from what the call site passed. **Such a line does
 * not collapse at all** — losing the saving is correct where losing the distinction is not.
 */
function collapseKey(level: string, event: string, ctx: Record<string, unknown>): string | null {
  const sessionId = ctx["sessionId"];
  const reason = ctx["reason"];
  if (typeof sessionId !== "string" && typeof reason !== "string") return null;
  // Sorted, so two call sites passing the same fields in a different order still collapse.
  const payload = Object.keys(ctx)
    .filter((k) => k !== "correlationId")
    .sort()
    .map((k) => k + "=" + String(ctx[k]))
    .join(SEP);
  return [level, event, payload].join(SEP);
}

/** First occurrence, then the 10th, 100th, 1,000th — a power of ten. */
function isMilestone(count: number): boolean {
  if (count === 1) return true;
  let n = count;
  while (n % 10 === 0) n /= 10;
  return n === 1;
}

/**
 * Wrap a logger so repeats collapse at the point the line is WRITTEN.
 *
 * Wrapping the composition root covers every call site at once, which is what makes this a
 * property of the daemon's logging rather than a discipline each call site has to remember.
 */
export function createCollapsingLogger(sink: Logger, now: () => number = Date.now): Logger {
  const runs = new Map<string, Run>();

  function emit(level: "debug" | "info" | "warn" | "error", event: string, ctx: Record<string, unknown>): void {
    const key = collapseKey(level, event, ctx);
    if (key === null) {
      sink[level](event, ctx);
      return;
    }

    const existing = runs.get(key);
    if (existing === undefined) {
      // Map insertion order is the eviction order, so deleting the first key drops the oldest run.
      if (runs.size >= LOG_COLLAPSE_MAX_KEYS) {
        const oldest = runs.keys().next();
        if (!oldest.done) runs.delete(oldest.value);
      }
      runs.set(key, { count: 1, firstAtMs: now() });
      sink[level](event, ctx);
      return;
    }

    existing.count += 1;
    if (!isMilestone(existing.count)) return;
    sink[level](event, {
      ...ctx,
      repeatedCount: existing.count,
      repeatWindowMs: now() - existing.firstAtMs,
    });
  }

  return {
    debug: (event, ctx) => { emit("debug", event, ctx); },
    info: (event, ctx) => { emit("info", event, ctx); },
    warn: (event, ctx) => { emit("warn", event, ctx); },
    error: (event, ctx) => { emit("error", event, ctx); },
  };
}
