/**
 * DOD-M15-SEAL-FAILED-TERMINAL-1 — a seal that FAILED is discoverable, not just a slow one.
 *
 * ─── The gap this closes ───────────────────────────────────────────────────────────────────────
 *
 * `DOD-M15-CLOSEWAIT-1` made the close answer at commitment and notarize in the background. Review
 * HIGH-1 pointed out the half that left open: a background ceremony that **throws** leaves the
 * session `active`, with a durable commitment, no receipt, and nothing retrying until a daemon
 * restart — while the agent is holding an `ok: true` and has no reason to suspect anything.
 *
 * `seal_in_progress` (added in that unit) distinguishes RUNNING from NO-CEREMONY. It cannot
 * distinguish either from DEAD. The only account of a dead one was a line in `daemon.log`, which is
 * not a surface an agent can read.
 *
 * ─── Why in memory and NOT a column on the session row ─────────────────────────────────────────
 *
 * The review said "persist … so it survives the read", and a database column is the reflex. It is
 * the wrong storage here, for a reason that is about correctness rather than cost:
 *
 * **A restart makes "failed" the wrong answer.** The boot sweep flips `active → interrupted,
 * interrupted_by='local'`, and `RestartSealResolver` then picks the session up and retries the seal.
 * So a persisted failure would outlive its own truth: the operator would read `seal_failed` about a
 * ceremony that is, at that moment, being retried. A marker whose lifetime is the process is exactly
 * right, because the condition it describes has the same lifetime.
 *
 * It also avoids a client-side schema migration, which this milestone treats as expensive on its own
 * terms — unrecoverable on an operator's machine if it goes wrong, and owed its own reviewed unit.
 * That is a real saving, but it is the second reason, not the first.
 */

export interface SealFailure {
  /** The upstream error, carried through rather than replaced with a label. */
  reason: string;
  /** ISO timestamp of the failure. */
  at: string;
}

/**
 * The last background seal failure per (agent, session), for the life of the process.
 *
 * Deliberately tiny and deliberately not exported as a singleton: the daemon owns one instance and
 * hands it to the writer (the close handler's detached tail) and the reader (`cello_sealed_receipt`),
 * so the two cannot drift onto different copies.
 */
export class SealFailureStore {
  readonly #failures = new Map<string, SealFailure>();

  #key(agentName: string, sessionId: string): string {
    // EXPLICIT ESCAPE, not a literal control character. It was a raw U+001F byte, which is
    // invisible in a diff, in a grep, and in most editors — I "proved" a key collision against a
    // hand-written copy of this function and only the real one disagreed. A separator nobody can
    // see is a separator someone will delete.
    return `${agentName}\x1f${sessionId}`;
  }

  /** Record a background ceremony that threw. */
  record(agentName: string, sessionId: string, reason: string, at: string): void {
    this.#failures.set(this.#key(agentName, sessionId), { reason, at });
  }

  /**
   * Forget any failure for this session.
   *
   * Called when a ceremony STARTS as well as when one succeeds. Starting matters: a re-close is the
   * documented remedy for a failed seal, and if the marker survived the retry the agent would be
   * told the seal is dead while it is running — the same "stale reading presented as current" defect
   * `DOD-M15-STALEROSTER-1` exists to stop, in a different subsystem.
   */
  clear(agentName: string, sessionId: string): void {
    this.#failures.delete(this.#key(agentName, sessionId));
  }

  get(agentName: string, sessionId: string): SealFailure | undefined {
    return this.#failures.get(this.#key(agentName, sessionId));
  }

  get size(): number {
    return this.#failures.size;
  }
}

/**
 * The agent-facing answer for a session whose background seal died.
 *
 * ORDERING MATTERS AND IS THE CALLER'S JOB: a RUNNING ceremony outranks a recorded failure, because
 * a re-close after a failure starts a new ceremony and the old marker must not shadow it. The read
 * handler checks `isSealing` first.
 */
export function describeSealFailed(opts: {
  sessionId: string;
  failure: SealFailure;
}): Record<string, unknown> {
  return {
    ok: false,
    reason: "seal_failed",
    seal_status: "failed",
    session_id: opts.sessionId,
    // The upstream cause, preserved. "The seal failed" tells an operator nothing about whether their
    // directory is unreachable, their agent is not started, or the carry was unusable.
    seal_failure_reason: opts.failure.reason,
    seal_failed_at: opts.failure.at,
    guidance:
      `The background seal ceremony for this session FAILED at ${opts.failure.at}: ` +
      `${opts.failure.reason}. This is not "still running" — nothing is retrying it right now. ` +
      "Your SEAL commitment is still durable and the conversation is intact, so the receipt is not " +
      "lost, only unproduced. Call cello_close_session again to start a fresh ceremony; the causes " +
      "are usually local and temporary (an agent that is not started, a directory this daemon " +
      "cannot currently reach — check cello_status). Do NOT use { force: true }: that abandons the " +
      "session and PERMANENTLY forfeits the receipt, which is the one outcome that cannot be undone. " +
      "Restarting the daemon also resolves it — the restart seal resolver retries orphaned " +
      "commitments on boot.",
  };
}
