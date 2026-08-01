/**
 * DOD-FRONTIER-STRAND-1 AC3 — a frontier mismatch, once seen, STAYS seen.
 *
 * Session `dbb93dfc…` sat unsealable for a week and nothing anywhere said so. A close was attempted,
 * refused with `seal_interrupted_rejected_by_counterparty`, and that was the end of it: the refusal
 * was a transient string in one command's output. `cello_sessions` went on listing the session as
 * plain `interrupted` — indistinguishable from one that is merely paused and will seal fine the
 * moment both parties are online. The operator had no way to tell "waiting" from "will never seal".
 *
 * So detection is not the gap; RETENTION is. The two frontiers can only be compared when the two
 * sides talk, which is the seal attempt — that is inherent, not a defect. What was missing is that
 * the answer was thrown away the instant it was produced, so the only way to learn the session was
 * stranded was to attempt another close and read the error again.
 *
 * This is in-memory on purpose, and the trade is stated rather than hidden: it survives for the
 * daemon's lifetime, not across a restart. Persisting it means a client-side schema migration on
 * every operator's machine (AC3 does not ask for one), and a mismatch is re-detected by the very
 * next close attempt anyway — so a restart costs one re-detection, never a wrong answer. What it
 * must never do is report a mismatch that is no longer true, which is why `clear()` exists and the
 * seal path calls it on success.
 */

/** The two frontiers, as the parties reported them, plus where they part company. */
export interface FrontierMismatch {
  /** Leaf count on THIS side. */
  readonly ours: number;
  /** Leaf count the counterparty reported. */
  readonly theirs: number;
  /** First index at which the two records can differ — the shorter side simply stops there. */
  readonly divergingLeafIndex: number;
  /** Epoch ms, so the operator can see whether this is fresh or a week old. */
  readonly observedAtMs: number;
}

/**
 * Bound: a daemon can hold many sessions over its lifetime and this map is never swept by anything
 * else. An unstated cap is a silent truncation, so it is named here and enforced by eviction of the
 * least-recently-written entry.
 */
const MAX_TRACKED_SESSIONS = 256;

/**
 * Eviction is FIFO-BY-WRITE, not LRU (review L2). `record()` refreshes an entry's position;
 * `get()` does not. Named accurately because the victim differs: a long-lived strand READ daily
 * but never re-observed is evicted ahead of a fresher unread one. That is acceptable here — a
 * mismatch is re-recorded on every close attempt, so anything actively being worked on is written,
 * not merely read — but calling it LRU would set the wrong expectation for whoever tunes it next.
 */

export class FrontierMismatchStore {
  readonly #byKey = new Map<string, FrontierMismatch>();

  static #key(agentName: string, sessionId: string): string {
    return `${agentName}\u0000${sessionId}`;
  }

  /**
   * Record a mismatch observed during a seal exchange. Overwrites any prior observation for the
   * same session — the newest numbers are the true ones, and a stale pair would be worse than none.
   */
  record(agentName: string, sessionId: string, m: Omit<FrontierMismatch, "observedAtMs">, nowMs: number): void {
    const key = FrontierMismatchStore.#key(agentName, sessionId);
    this.#byKey.delete(key); // re-insert so this session moves to the young end of the eviction order
    this.#byKey.set(key, { ...m, observedAtMs: nowMs });
    while (this.#byKey.size > MAX_TRACKED_SESSIONS) {
      const oldest = this.#byKey.keys().next();
      if (oldest.done === true) break;
      this.#byKey.delete(oldest.value);
    }
  }

  /** What was observed for this session, or null. */
  get(agentName: string, sessionId: string): FrontierMismatch | null {
    return this.#byKey.get(FrontierMismatchStore.#key(agentName, sessionId)) ?? null;
  }

  /**
   * Forget a session's mismatch.
   *
   * Called when a seal SUCCEEDS: the frontiers evidently agree now, so continuing to flag the
   * session would be the same defect pointing the other way — an operator told a healthy session is
   * stranded stops believing the flag, and the next real strand reads as noise.
   */
  clear(agentName: string, sessionId: string): void {
    this.#byKey.delete(FrontierMismatchStore.#key(agentName, sessionId));
  }
}

/**
 * Render a retained mismatch for the session list.
 *
 * Extracted rather than left inline in `daemon.ts` so it can be TESTED: the AC asks for a
 * `cello_sessions` field, and an inline closure inside `buildInterruptedSessions` can only be
 * reached by standing up a whole daemon and driving a real seal exchange. A pure function is the
 * honest seam — the store is tested above, this is tested directly, and `daemon.ts` just calls it.
 */
export function renderFrontierMismatch(
  m: FrontierMismatch,
  sessionId: string,
): { ours: number; theirs: number; divergingLeafIndex: number; observedAt: string; guidance: string } {
  return {
    ours: m.ours,
    theirs: m.theirs,
    divergingLeafIndex: m.divergingLeafIndex,
    observedAt: new Date(m.observedAtMs).toISOString(),
    // Says what is wrong, then what to do, then why it is terminal — an operator reading this on a
    // week-old session needs all three, and the old refusal gave none of them.
    guidance: `This session cannot seal: you hold ${m.ours} messages, the counterparty holds ${m.theirs}, and the records diverge at leaf ${m.divergingLeafIndex}. Compare that message on both transcripts with cello_transcript ${sessionId}. A leaf that only one side recorded can never be co-signed.`,
  };
}
