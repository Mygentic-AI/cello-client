/**
 * DOD-MP-SESSION-RETIRE-1 — what this daemon DOES when the relay says a session is over.
 *
 * ── WHY THIS IS A MODULE AND NOT A BRANCH IN `sendContent` ────────────────────────────────────
 *
 * It was a branch, and that is precisely why it knew without acting. Reaching it requires a live
 * `#activeNodes` entry holding a real relay client and a real session node — state no unit test can
 * construct — so nothing could assert the response, and the response was: log it, refuse the send,
 * and leave the local row saying `active`.
 *
 * The seam that has to be substituted to test this is the RELAY'S ANSWER. The thing under test is
 * what we do about it. Keeping them in one function meant you could not have the second without
 * faking the first, which is the shape that makes a test agree with whatever the code does.
 *
 * ── WHY RETIRING THE ROW IS THE WHOLE POINT ───────────────────────────────────────────────────
 *
 * The relay pushes `session_sealed` exactly once. A daemon that is down or restarting at that
 * instant never records it, so this side keeps a row saying `active` for a session the relay has
 * finished. Everything that picks a session by local status then picks THAT one, forever:
 * `activeSessionsWith` filters on `status === "active"` and only opens a fresh session when nothing
 * matches. So a stale row is not merely stale — it is a permanent block on ever opening the
 * replacement.
 *
 * Observed live 2026-08-13: the document delivery worker resubmitted the same sealed session every
 * 60 seconds, was told terminally each time, and the row survived `cello logout && cello login`
 * because it is persisted. Nothing recovered on its own, and the only symptom was a pending count
 * that never fell.
 *
 * The CONVERSATION path already handles this by telling a human to start a new session, and the
 * guidance below still says so because that advice is right for a human. **Document delivery has no
 * human in the loop**, so the daemon must act for them — availability and fallback are first-class
 * protocol concerns, and a route whose only session is dead has no fallback at all.
 *
 * Marking it sealed is also simply TRUE. The relay is the authority on whether it will witness
 * again, and this message is the relay saying no.
 */

export interface TerminalRefusalDeps {
  logger: { error(event: string, ctx: Record<string, unknown>): void };
  /**
   * Retire the local session row. REQUIRED — a no-op default would restore the exact defect this
   * module exists to remove, and it would do it silently.
   */
  retireSession(sessionId: string): void;
}

export interface TerminalRefusalInput {
  sessionId: string;
  /** The relay's own reason — `session_sealed` or `session_not_found`. */
  reason: string;
  correlationId: string | undefined;
}

export interface TerminalRefusalResult {
  ok: false;
  reason: string;
  error: string;
  /** Never durable: there is no later attempt that can succeed on this session. */
  durable: false;
  guidance: string;
}

export function terminalRelayRefusal(
  deps: TerminalRefusalDeps,
  input: TerminalRefusalInput,
): TerminalRefusalResult {
  deps.logger.error("session.relay.hash.submit.terminal", {
    sessionId: input.sessionId,
    reason: input.reason,
    correlationId: input.correlationId,
    impact: "the relay has ended this session — nothing sent now can ever be part of its record",
  });
  // RETIRE FIRST, then report. If the caller's report path ever throws, the row is already correct;
  // the reverse ordering would leave the daemon reporting a refusal it had not acted on.
  deps.retireSession(input.sessionId);
  return {
    ok: false,
    reason: input.reason,
    error:
      input.reason === "session_sealed"
        ? "the relay has already sealed this session, so nothing further can enter its record"
        : "the relay no longer holds this session, so nothing further can enter its record",
    durable: false,
    guidance:
      `This session is over as far as the relay is concerned, and anything sent now would be ` +
      `invisible to the receipt. Nothing was sent, and this daemon has now retired the session on ` +
      `its side, so the next send will start a fresh one. The conversation so far is not lost.`,
  };
}
