/**
 * DOD-M12B-RESTART-SEAL-1 — resolve the sessions our own stop orphaned, with a receipt.
 *
 * A daemon shutdown flips every open session to `interrupted` on the way out, and nothing has ever
 * moved them again: their transport keypairs died with the process, so they cannot be resumed, and
 * the only exit is `cello_close_session {force:true}`, which forfeits the notarized receipt.
 *
 * This walks them on startup and SEALS them instead — bilateral if the counterparty answers,
 * unilateral once the directory's delivery grace has elapsed. When the directory refuses
 * `seal_unilateral_too_early` it hands back exactly how long is left; that number becomes a
 * scheduled retry rather than a sentence asking a human to come back.
 *
 * SCOPE IS THE WHOLE SAFETY ARGUMENT. `listRestartOrphans` returns only sessions marked
 * `interrupted_by = 'local'` — ours. A session the COUNTERPARTY ended, or one lost with the relay
 * witness stream, is never touched here, so SI-001 ("no auto-seal on a session_interrupted receipt —
 * a daemon that sealed on its own would notarize a conversation nobody chose to end") keeps holding
 * for the live interruption it was written about.
 *
 * Serial and staggered on purpose: a seal is a directory ceremony, and a machine holding hundreds of
 * orphans must not answer a restart with hundreds of simultaneous ceremonies.
 */
import type { Logger } from "./types.js";

/** A session our own stop left behind. */
export interface RestartOrphan {
  agentName: string;
  sessionId: string;
  messageCount: number;
}

/**
 * The result of one seal attempt. `retryAfterSeconds` is the directory's own countdown from
 * `seal_unilateral_too_early` — the delivery grace that has to elapse before a unilateral seal is
 * allowed. It is a WAIT the directory named, not a guess.
 */
export type SealOutcome =
  | { ok: true }
  | {
      ok: false;
      reason: string;
      retryAfterSeconds?: number;
      /** The close path's own guidance. Carried, never replaced — see the give-up log. */
      guidance?: string;
      /** Everything the close computed about WHY, so `reason` stops being the only fact. */
      detail?: Record<string, unknown>;
    };

export interface ScheduledTask {
  cancel: () => void;
}

export interface RestartSealResolverDeps {
  logger: Logger;
  /** Sessions with status 'interrupted' AND interrupted_by 'local'. Nothing else is eligible. */
  listRestartOrphans: () => RestartOrphan[];
  sealSession: (agentName: string, sessionId: string) => Promise<SealOutcome>;
  /**
   * Record DURABLY that this session was given up on, so the next boot does not start over.
   * Without it a machine restarting ~6 times a day re-attempts a hopeless session forever.
   *
   * REQUIRED, not optional. There is exactly one composition root, so optionality buys nothing and
   * costs the compiler's ability to catch a wiring that was never done — and the whole
   * justification for the two new columns is that this call happens.
   */
  markGaveUp: (agentName: string, sessionId: string, reason: string) => void;
  now?: () => number;
  schedule?: (fn: () => void, ms: number) => ScheduledTask;
  /** Gap between two seal attempts. */
  staggerMs?: number;
  /**
   * How long to wait after boot before the first attempt. A seal needs the directory, and at the
   * instant the daemon finishes starting, signaling is still being established — firing
   * immediately would spend an attempt on a connection that does not exist yet.
   */
  initialDelayMs?: number;
  /** Hard ceiling on attempts for one session before it is reported as needing a manual decision. */
  maxAttemptsPerSession?: number;
  /**
   * Ceiling on ONE seal attempt. A close that never settles would otherwise leave `#running` true
   * with no timer armed and no log line — the resolver stalls, holding a full queue, silently.
   */
  attemptTimeoutMs?: number;
}

/**
 * Refusals no retry can ever help, so they cost ONE attempt and not fifteen minutes.
 *
 * Measured 2026-08-17 across 443 submitted seal leaves and 183 completed seals — 59% of seals that
 * start never finish, and these are the reasons where trying again is not persistence:
 *
 *   session_abandoned                          10× — terminal by definition; the receipt is gone.
 *   leaf_count_mismatch                         4× — the two trees genuinely disagree.
 *   seal_interrupted_rejected_by_counterparty  18× — they said NO. Asking again is worse than
 *                                                    noise: it is a machine badgering a peer who
 *                                                    already declined.
 *
 * `session_incomplete` and `seal_unilateral_timeout` are deliberately NOT here. The first can be
 * fixed by a relay pull filling the gap — the close's own guidance says so — and the second is a
 * directory that did not answer in time, which the next attempt may well get.
 */
const TERMINAL_SEAL_REFUSALS: ReadonlySet<string> = new Set([
  "session_abandoned",
  "seal_interrupted_rejected_by_counterparty",
  "session_already_sealed",
  // OUR OWN verification finding a genuine divergence between the two trees. Distinct from the
  // counterparty's `leaf_count_mismatch`, which never reaches here as a top-level reason — it
  // arrives as `detail.rejection_reason` under the rejection above. Naming the bare string here
  // was inert: the close cannot produce it.
  "seal_interrupted_leaf_count_mismatch",
  "session_not_found",
  // The relay released the session (it drops one 24 h after the last message), so there is nothing
  // left for any directory to rebuild the record from. No amount of retrying brings it back.
  "seal_carry_empty",
  // Not protocol outcomes — a wiring or caller fault. Retrying re-runs the same bug.
  "session_not_closeable",
  "close_handler_missing",
  "missing_params",
]);

const DEFAULT_STAGGER_MS = 5_000;
/** Long enough for the directory handshake started moments earlier to have landed. */
const DEFAULT_INITIAL_DELAY_MS = 30_000;
const DEFAULT_MAX_ATTEMPTS = 5;
/** Backoff for a failure the directory gave no deadline for. Doubles, so a bounded run spans ~1 h. */
const BASE_BACKOFF_MS = 60_000;
/** Generous: a close does discovery, a broker dial, a relay submit and a directory round. */
const DEFAULT_ATTEMPT_TIMEOUT_MS = 120_000;

interface QueueItem {
  orphan: RestartOrphan;
  attempts: number;
  nextAt: number;
}

function defaultSchedule(fn: () => void, ms: number): ScheduledTask {
  const t = setTimeout(fn, ms);
  // A background resolver must never be the reason a daemon will not exit.
  t.unref?.();
  return { cancel: () => clearTimeout(t) };
}

export class RestartSealResolver {
  readonly #deps: RestartSealResolverDeps;
  readonly #now: () => number;
  readonly #schedule: (fn: () => void, ms: number) => ScheduledTask;
  readonly #staggerMs: number;
  readonly #maxAttempts: number;
  readonly #initialDelayMs: number;
  readonly #attemptTimeoutMs: number;
  /** Resolves when no attempt is in flight — awaited by stop() so a shutdown does not cut a
   *  ceremony in half and leave the two sides permanently divergent. */
  #inFlight: Promise<unknown> | null = null;

  readonly #queue = new Map<string, QueueItem>();
  #timer: ScheduledTask | null = null;
  #started = false;
  #stopped = false;
  #running = false;

  constructor(deps: RestartSealResolverDeps) {
    this.#deps = deps;
    this.#now = deps.now ?? (() => Date.now());
    this.#schedule = deps.schedule ?? defaultSchedule;
    this.#staggerMs = deps.staggerMs ?? DEFAULT_STAGGER_MS;
    this.#maxAttempts = deps.maxAttemptsPerSession ?? DEFAULT_MAX_ATTEMPTS;
    this.#initialDelayMs = deps.initialDelayMs ?? DEFAULT_INITIAL_DELAY_MS;
    this.#attemptTimeoutMs = deps.attemptTimeoutMs ?? DEFAULT_ATTEMPT_TIMEOUT_MS;
  }

  /** Enqueue every restart orphan and begin working through them. Idempotent. */
  start(): void {
    if (this.#started || this.#stopped) return;
    this.#started = true;

    let orphans: RestartOrphan[];
    try {
      orphans = this.#deps.listRestartOrphans();
    } catch (err: unknown) {
      // ABSENT IS NOT FINE. If we cannot read the list, say so — silence here reads exactly like
      // "there was nothing to resolve", which is the state this unit exists to end.
      this.#deps.logger.error("session.restart_seal.enumerate.failed", {
        error: err instanceof Error ? err.message : String(err),
        impact: "sessions the last shutdown orphaned will stay interrupted and unsealed",
      });
      return;
    }

    if (orphans.length === 0) return;

    const now = this.#now();
    const firstAt = now + this.#initialDelayMs;
    for (const orphan of orphans) {
      this.#queue.set(`${orphan.agentName}:${orphan.sessionId}`, { orphan, attempts: 0, nextAt: firstAt });
    }
    this.#deps.logger.info("session.restart_seal.enqueued", {
      count: orphans.length,
      impact: "sessions the last shutdown left open will be sealed rather than left for a force-abandon",
    });
    this.#arm(this.#initialDelayMs);
  }

  /**
   * Stop, and start nothing further. A shutdown that keeps opening directory ceremonies is not
   * draining (DOD-M12B-SHUTDOWN-1) — and the flag, not the cancelled timer, is what an attempt
   * already in flight checks when it lands.
   */
  stop(): Promise<void> {
    this.#stopped = true;
    this.#timer?.cancel();
    this.#timer = null;
    this.#queue.clear();
    // AWAIT what is already in flight. Severing signaling under a half-finished seal-interrupted
    // exchange leaves the counterparty holding a commitment we never acknowledged: their session
    // advances to `seal_interrupted_pending` and ours stays `interrupted`, permanently divergent
    // and produced automatically on every shutdown.
    //
    // WHAT IS AWAITED IS THE BOUNDED RACE, NOT THE CLOSE. Returning the raw `sealSession` promise
    // would hang shutdown forever on a close that never settles — and shutdown holds the SQLCipher
    // write lock, so "forever" means a daemon that cannot be restarted. `attemptTimeoutMs` bounds
    // this wait because the raced promise is what is stored.
    return this.#inFlight ? this.#inFlight.then(() => undefined, () => undefined) : Promise.resolve();
  }

  /** Arm the next pass only while there is still work. An empty queue must leave NO timer behind —
   *  a resolver that keeps a dead timer alive is a resolver that shows up in a shutdown trace. */
  #armIfWork(): void {
    if (this.#queue.size === 0) return;
    this.#arm(this.#staggerMs);
  }

  #arm(delayMs: number): void {
    if (this.#stopped) return;
    this.#timer?.cancel();
    this.#timer = this.#schedule(() => {
      this.#timer = null;
      void this.#pump();
    }, delayMs);
  }

  async #pump(): Promise<void> {
    if (this.#stopped || this.#running) return;
    if (this.#queue.size === 0) return;

    const now = this.#now();
    let due: QueueItem | null = null;
    for (const item of this.#queue.values()) {
      if (item.nextAt <= now && (due === null || item.nextAt < due.nextAt)) due = item;
    }

    if (due === null) {
      // Nothing is due yet — sleep until the earliest deadline rather than polling.
      let earliest = Infinity;
      for (const item of this.#queue.values()) earliest = Math.min(earliest, item.nextAt);
      if (earliest !== Infinity) this.#arm(Math.max(0, earliest - now));
      return;
    }

    const item = due;
    const key = `${item.orphan.agentName}:${item.orphan.sessionId}`;
    item.attempts += 1;
    this.#running = true;

    let outcome: SealOutcome;
    let attemptTimer: ScheduledTask | null = null;
    try {
      const attempt = this.#deps.sealSession(item.orphan.agentName, item.orphan.sessionId);
      // A close that never settles must not wedge the queue silently.
      const timeout = new Promise<SealOutcome>((resolve) => {
        attemptTimer = this.#schedule(
          () => resolve({ ok: false, reason: "restart_seal_attempt_timeout" }),
          this.#attemptTimeoutMs,
        );
      });
      // The RACE is what stop() awaits — see stop(). Storing the raw attempt here would make a
      // hung close a hung shutdown; storing the race makes the wait bounded by attemptTimeoutMs.
      const raced = Promise.race([attempt, timeout]);
      this.#inFlight = raced;
      // A rejected `attempt` still settles the race, and #inFlight is only ever awaited with both
      // handlers attached (stop()), so this cannot surface as an unhandled rejection.
      attempt.catch(() => { /* handled below via the race */ });
      outcome = await raced;
    } catch (err: unknown) {
      outcome = { ok: false, reason: err instanceof Error ? err.message : String(err) };
    } finally {
      (attemptTimer as ScheduledTask | null)?.cancel();
      this.#inFlight = null;
      this.#running = false;
    }

    // Re-checked AFTER the await: stop() can land while a ceremony is in flight, and the queue it
    // cleared must not be repopulated by this attempt's bookkeeping.
    if (this.#stopped) return;

    if (outcome.ok) {
      this.#queue.delete(key);
      this.#deps.logger.info("session.restart_seal.resolved", {
        agentName: item.orphan.agentName,
        sessionId: item.orphan.sessionId,
        attempts: item.attempts,
        messageCount: item.orphan.messageCount,
      });
      this.#armIfWork();
      return;
    }

    const terminal = TERMINAL_SEAL_REFUSALS.has(outcome.reason);
    if (terminal || item.attempts >= this.#maxAttempts) {
      this.#queue.delete(key);
      // DURABLE, so the next boot does not start the same five attempts over. A machine restarting
      // ~6 times a day would otherwise re-try a hopeless session forever, which is the burst the
      // stagger exists to prevent, merely spread out.
      try { this.#deps.markGaveUp(item.orphan.agentName, item.orphan.sessionId, outcome.reason); }
      catch (err: unknown) {
        this.#deps.logger.warn("session.restart_seal.mark_gave_up.failed", {
          sessionId: item.orphan.sessionId,
          error: err instanceof Error ? err.message : String(err),
          impact: "this session will be re-attempted on every future boot",
        });
      }
      this.#deps.logger.warn("session.restart_seal.gave_up", {
        agentName: item.orphan.agentName,
        sessionId: item.orphan.sessionId,
        attempts: item.attempts,
        reason: outcome.reason,
        // WHY it stopped, not just that it did. "We stopped because they refused" and "we stopped
        // because we ran out of tries" are different facts and lead to different operator actions.
        stoppedBecause: terminal ? "refusal_is_terminal" : "attempts_exhausted",
        // The detail the close COMPUTED and used to drop one function later: which of the six
        // causes behind `seal_interrupted_rejected_by_counterparty` this was, and the leaf counts
        // that identify a frontier strand.
        ...(outcome.detail ? { detail: outcome.detail } : {}),
        // THE CLOSE'S OWN GUIDANCE WINS. A fixed string here told the operator to force-abandon —
        // and for `session_already_sealed` the close handler says in capitals NOT to, because
        // forcing there permanently forfeits a half that is still recoverable.
        guidance:
          outcome.guidance ??
          ("This session could not be sealed automatically and is still interrupted. Close it with " +
           "cello_close_session, or force-abandon it — which ends it WITHOUT a notarized receipt."),
      });
      this.#armIfWork();
      return;
    }

    // The directory named a deadline: wait exactly that long. Anything else either batters it with
    // refusals or leaves the session sitting after the grace has elapsed.
    const waitMs =
      typeof outcome.retryAfterSeconds === "number" && outcome.retryAfterSeconds >= 0
        ? outcome.retryAfterSeconds * 1_000
        : BASE_BACKOFF_MS * 2 ** (item.attempts - 1);

    item.nextAt = this.#now() + waitMs;
    this.#deps.logger.info("session.restart_seal.waiting", {
      agentName: item.orphan.agentName,
      sessionId: item.orphan.sessionId,
      attempts: item.attempts,
      reason: outcome.reason,
      ...(typeof outcome.retryAfterSeconds === "number" ? { retryAfterSeconds: outcome.retryAfterSeconds } : {}),
      retryInMs: waitMs,
    });
    this.#arm(Math.min(this.#staggerMs, waitMs));
  }
}
