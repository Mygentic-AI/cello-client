/**
 * DOD-MP-SESSION-RETIRE-1, the remaining half — route around a session that keeps refusing,
 * WITHOUT destroying anything.
 *
 * ── WHY NOT JUST ADD THE STRING TO THE TERMINAL SET ───────────────────────────────────────────
 *
 * The fully-sealed case answers **`relay_session_gone`**, and the obvious fix is to add it to
 * `TERMINAL_RELAY_REFUSALS` so the session is retired like `session_sealed`. That is refused, on
 * evidence: `relay-node.ts` defaults to `InMemoryRelayStore`, so a relay restart or a MIG roll
 * wipes every session it holds and every client is then told `relay_session_gone` for sessions that
 * are perfectly alive. Made terminal, one relay bounce would retire every live session on every
 * client — an unreachable node making the system unusable instead of being routed around, which is
 * the sovereign-node invariant exactly inverted.
 *
 * The string conflates two facts — *"this session is over"* and *"the relay lost its memory"* — and
 * destroying durable local state on the ambiguous one is wrong under one of the two readings.
 *
 * ── WHAT THIS DOES INSTEAD ────────────────────────────────────────────────────────────────────
 *
 * Nothing is retired, marked, or deleted. A session that has refused repeatedly simply stops being
 * REUSED by document delivery, so the next acquire opens a fresh one. That is correct under BOTH
 * readings: if the session really is finished, delivery routes around it; if the relay merely
 * bounced, the cost is one extra session and the old one remains untouched — still listed, still
 * usable by the conversation path, still holding its record.
 *
 * DELIBERATELY IN MEMORY. This is a routing hint, not a judgement about the session, and a restart
 * is precisely when a stale local opinion should be discarded rather than preserved. Nothing here
 * belongs in the database; putting it there would be the destructive fix wearing a smaller hat.
 */

/**
 * The refusals that say something about THE SESSION rather than about the peer.
 *
 * `relay_session_gone` is here and NOT in `TERMINAL_RELAY_REFUSALS` — that separation is the unit.
 * An offline counterparty is excluded on purpose: abandoning a session because the far end is
 * asleep would open a fresh session on every sweep for as long as they stay away.
 */
export const TERMINAL_ISH_REFUSALS: ReadonlySet<string> = new Set([
  "session_sealed",
  "session_not_found",
  "relay_session_gone",
]);

/** Consecutive terminal-ish refusals before delivery stops reusing a session. */
export const SUSPECT_THRESHOLD = 2;

/** Bounded so a long-lived daemon cannot accumulate a row per session it ever gave up on. */
export const SUSPECT_MAX_TRACKED = 256;

export interface SessionSuspects {
  /** Record a refusal. Only terminal-ish reasons count toward suspicion. */
  noteFailure(sessionId: string, reason: string): void;
  /** A send worked — the run is broken, so the count resets. */
  noteSuccess(sessionId: string): void;
  /** Should document delivery avoid REUSING this session? */
  isSuspect(sessionId: string): boolean;
  /** Tracked-session count, for the bound's test. */
  size(): number;
}

export function createSessionSuspects(
  opts: { threshold?: number; maxTracked?: number } = {},
): SessionSuspects {
  const threshold = opts.threshold ?? SUSPECT_THRESHOLD;
  const maxTracked = opts.maxTracked ?? SUSPECT_MAX_TRACKED;
  // Insertion-ordered, so the oldest entry is the first key — a Map is the eviction order already.
  const runs = new Map<string, number>();

  return {
    noteFailure(sessionId: string, reason: string): void {
      if (!TERMINAL_ISH_REFUSALS.has(reason)) return;
      const next = (runs.get(sessionId) ?? 0) + 1;
      // Re-insert so a session we are actively judging is the LAST to be evicted; otherwise the
      // bound could drop the very session about to cross the threshold.
      runs.delete(sessionId);
      runs.set(sessionId, next);
      while (runs.size > maxTracked) {
        const oldest = runs.keys().next();
        if (oldest.done === true) break;
        runs.delete(oldest.value);
      }
    },
    noteSuccess(sessionId: string): void {
      runs.delete(sessionId);
    },
    isSuspect(sessionId: string): boolean {
      return (runs.get(sessionId) ?? 0) >= threshold;
    },
    size(): number {
      return runs.size;
    },
  };
}
