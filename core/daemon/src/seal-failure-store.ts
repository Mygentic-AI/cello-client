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
 *
 * ─── The two populations the restart does NOT retry (review MEDIUM-6) ──────────────────────────
 *
 * The argument above holds for an ordinary conversation, and that was verified rather than assumed.
 * `listRestartOrphanedSessions` excludes two shapes, and this docstring used to imply neither
 * existed:
 *
 *   `message_count > 0` — a closed session that carried no messages is never retried. Harmless: no
 *   receipt was obtainable over nothing.
 *
 *   `restart_seal_gave_up_at IS NULL` — a session the resolver already exhausted. This one WAS a
 *   real hole: nothing ever cleared that column, so a gave-up session that was later revived, used,
 *   and closed could lose its in-memory marker at restart, be excluded from recovery forever, and
 *   then be force-abandoned by the revival sweep (which explicitly includes `IS NOT NULL`) — a
 *   receipt permanently forfeited with no surface ever saying so. `reviveSessionNode` now clears it:
 *   a session something is talking to again is not the "hopeless session" the column was written for.
 */

export interface SealFailure {
  /** The upstream error, carried through rather than replaced with a label. */
  reason: string;
  /** ISO timestamp of the failure. */
  at: string;
  /**
   * HOW the ceremony died, and this distinction is the whole of review HIGH-1.
   *
   * The first cut recorded only on the detached tail's `.catch` — and `escalateToUnilateralSeal`
   * contains **zero `throw`s**. All nine of its failure paths RESOLVE with `{ ok: false, reason }`:
   * `seal_unilateral_timeout`, `seal_carry_empty`, `seal_counterparty_pending`,
   * `seal_agent_key_unavailable`, and the rest. So every ordinary dead ceremony landed on the branch
   * that recorded nothing, and the receipt surface answered `not_sealed_yet` exactly as before — the
   * unit closed roughly a tenth of the gap it was written for, and its own test had to INJECT a
   * throwing key provider to reach the path it covered.
   *
   *   `unresolved` — the ceremony ran to completion and produced no receipt. The common case.
   *   `threw`      — an exception escaped it. Rare, and usually a local fault (a locked key vault,
   *                  a DB error) rather than anything about the conversation.
   *
   * They get different guidance, because they have different fixes.
   */
  kind: "unresolved" | "threw";
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

  /** Record a background ceremony that ended without a receipt — resolved OR thrown. */
  record(agentName: string, sessionId: string, reason: string, at: string, kind: SealFailure["kind"]): void {
    this.#failures.set(this.#key(agentName, sessionId), { reason, at, kind });
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
  const threw = opts.failure.kind === "threw";
  return {
    ok: false,
    reason: "seal_failed",
    // Two different facts, two different words. "failed" is an exception; "unresolved" is a ceremony
    // that ran and produced nothing, which is the ordinary shape and often means the counterparty
    // simply has not closed yet.
    seal_status: threw ? "failed" : "unresolved",
    session_id: opts.sessionId,
    // The upstream cause, preserved. "The seal failed" tells an operator nothing about whether their
    // directory is unreachable, their agent is not started, or the carry was unusable.
    seal_failure_reason: opts.failure.reason,
    seal_failed_at: opts.failure.at,
    guidance: threw
      ? `The background seal ceremony for this session hit an ERROR at ${opts.failure.at}: ` +
        `${opts.failure.reason}. This is not "still running" — nothing is retrying it. An exception ` +
        "here is usually a LOCAL fault (a key that could not be loaded, a database error) rather " +
        "than anything about the conversation, so check the daemon log around that timestamp. Your " +
        "SEAL commitment is still durable and the conversation is intact: the receipt is unproduced, " +
        "not lost. Call cello_close_session again once the local cause is addressed. Do NOT use " +
        "{ force: true } — that abandons the session and PERMANENTLY forfeits the receipt, the one " +
        "outcome that cannot be undone."
      : `The background seal ceremony for this session finished at ${opts.failure.at} WITHOUT ` +
        `producing a receipt: ${opts.failure.reason}. This is not "still running" — nothing is ` +
        "retrying it right now. Read the reason before acting: seal_counterparty_pending and " +
        "seal_unilateral_timeout mean the other side has not closed yet, and the fix is to wait for " +
        "them (or retry later, once the directory's delivery-grace window has elapsed and a " +
        "unilateral seal becomes available). Reasons naming this daemon — an agent that is not " +
        "started, a directory it cannot reach — are fixed locally; check cello_status. Your SEAL " +
        "commitment is durable and the conversation is intact, so the receipt is unproduced rather " +
        "than lost. Retry with cello_close_session. Do NOT use { force: true }: that abandons the " +
        "session and PERMANENTLY forfeits the receipt.",
  };
}
