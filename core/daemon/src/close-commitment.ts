/**
 * DOD-M15-CLOSEWAIT-1 — the answer a close gives at COMMITMENT, before notarization.
 *
 * ─── What this replaces ────────────────────────────────────────────────────────────────────────
 *
 * `cello_close_session` used to block until the seal ceremony finished. Measured 2026-08-17: leaf
 * submitted 16:48:55, ceremony completed 17:00:01 — **11 minutes 6 seconds of a frozen command.**
 *
 * It was working the whole time: the SEAL leaf was submitted, and it was waiting for the
 * counterparty to close too, escalating to a unilateral seal if they never did. But an operator
 * watching a dead terminal concluded it was broken and force-abandoned **seventeen sessions** —
 * which forfeits the exact receipt the wait was earning. A UX failure that destroys the artifact is
 * worse than the wait it was protecting.
 *
 * ─── The contract (Decisions Carried #4, decided before this code) ─────────────────────────────
 *
 * ANSWER ON COMMITMENT, NOT ON NOTARIZATION. Nothing about what is signed, by whom, or in what
 * order changes; only the IPC response stops waiting for it.
 *
 * ─── The counterbalance this file exists to hold ───────────────────────────────────────────────
 *
 * The danger in answering early is the opposite of the one it fixes: an operator who believes a
 * COMMITTED session is a SEALED one is worse off than one who is merely kept waiting, because they
 * will never fetch the receipt. So this response:
 *
 *   - carries NO `sealed_root` and NO `sealed` field — there is nothing notarized yet to name;
 *   - says `seal_status: "committed"`, a word that is not "closed" and not "sealed";
 *   - names `cello_get_sealed_receipt`, or the status is one an agent can do nothing with;
 *   - says the receipt is NOT YET available, so an agent polling immediately does not read an empty
 *     answer as failure;
 *   - warns what `force` costs, because that is the move the 11-minute freeze actually provoked.
 *
 * ONE definition, exported, used at every call site — a second copy is how two surfaces come to
 * disagree after one of them is reworded.
 */

/** The guidance string for a committed-not-yet-notarized close. */
export function CLOSE_COMMITTED_GUIDANCE(opts: { sessionId: string; deadlineMs: number }): string {
  const minutes = Math.max(1, Math.round(opts.deadlineMs / 60_000));
  return (
    `Your SEAL commitment for session ${opts.sessionId} is recorded and the notarization is now ` +
    `running in the background. The receipt is NOT YET available: the seal completes as soon as the ` +
    `counterparty also closes, and if they never do it escalates to a unilateral seal after about ` +
    `${minutes} minutes. Fetch it with cello_sealed_receipt (session_id ${opts.sessionId}) — an ` +
    `empty answer before then means "still running", not "failed". Do NOT re-close with force:true ` +
    `to hurry it: forcing ABANDONS the session and forfeits the receipt this is earning, which is ` +
    `exactly how seventeen sessions were lost when this call used to block. If the daemon restarts ` +
    `before the seal finishes, it resumes the notarization on its next start.`
  );
}

/**
 * The full response body for a close that has committed but not yet notarized.
 *
 * Deliberately NOT `{ ok: true, sealed_root }`-shaped. `ok: true` is correct — the operation the
 * caller asked for succeeded, their commitment is durable — but every field that would imply a
 * finished seal is absent by construction rather than by remembering to omit it.
 */
export function describeSealCommitted(opts: {
  sessionId: string;
  deadlineMs: number;
}): Record<string, unknown> {
  return {
    ok: true,
    session_id: opts.sessionId,
    seal_status: "committed",
    guidance: CLOSE_COMMITTED_GUIDANCE(opts),
  };
}
