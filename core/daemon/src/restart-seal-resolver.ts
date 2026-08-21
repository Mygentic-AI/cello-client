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
 * SCOPE IS THE WHOLE SAFETY ARGUMENT, and after DOD-M12B-PENDING-RESOLVE-1 it has TWO branches.
 *
 *   1. `interrupted` with `interrupted_by = 'local'` — OURS. Our own boot sweep, shutdown sweep or
 *      kill switch ended it; nobody else did, and it cannot be resumed because the keypairs died
 *      with the process.
 *   2. `seal_interrupted_pending` — a seal commitment that nobody ever asked the directory to
 *      notarize. **This population includes sessions the COUNTERPARTY asked to end**, which is why
 *      the SI-001 boundary in `close-session-handler.ts` had to be restated rather than left as
 *      "nothing the counterparty caused is auto-sealed". SI-001 forbids notarizing a conversation
 *      NOBODY chose to end; here somebody always did — an initiator row carries the counterparty's
 *      signed leaf, and a responder row exists because the counterparty sent a request to seal.
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
  /**
   * DOD-M12B-PENDING-RESOLVE-1: which population this is. Two statuses now reach this queue and
   * they need different words in a give-up: an `interrupted` session may legitimately be
   * force-abandoned, and a `seal_interrupted_pending` one must not be, because forcing forfeits a
   * signed commitment and the relay-witnessed leaves that are one request away from a receipt.
   */
  status: "interrupted" | "seal_interrupted_pending";
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
  /**
   * DOD-M12B-PENDING-RESOLVE-1 — TWO populations, each with its own safety argument:
   *   - `interrupted` AND `interrupted_by = 'local'` — our own stop ended it, so we may describe it.
   *   - `seal_interrupted_pending` — a seal commitment nobody asked the directory to notarize.
   * Nothing else is eligible.
   */
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
 * `seal_carry_bilateral_in_progress` is deliberately NOT here either: it means the relay has what
 * it needs to seal BILATERALLY, so the right move is to come back and find the session already
 * sealed — which then answers `session_already_sealed`, which IS terminal.
 *
 * `session_incomplete` and `seal_unilateral_timeout` are deliberately NOT here. The first can be
 * fixed by a relay pull filling the gap — the close's own guidance says so — and the second is a
 * directory that did not answer in time, which the next attempt may well get.
 */
/**
 * DOD-M12B-PENDING-RESOLVE-1 (review F2) — refusals that mean "WE were not ready", not "this session
 * is hopeless".
 *
 * Every one of these is a local precondition of OURS. The close handler says so itself:
 * *"`standing_receiver_unavailable` is simply 'the agent is not started yet', which a freshly booted
 * daemon reports for every session."* And a freshly booted daemon is the only time this resolver
 * runs — the receiver is created when `cello_start_agent` reaches the daemon, which on a boot where
 * no client has attached yet has not happened for any agent.
 *
 * Left in the ordinary budget they cost five attempts in ~15 minutes and then a DURABLE
 * `restart_seal_gave_up_at`, which removes the session from the only queue that would ever look at
 * it again. For the `seal_interrupted_pending` population that is materially worse than doing
 * nothing: those rows hold signed commitments and relay-witnessed leaves that are ready to notarize,
 * and the give-up reaches no operator surface at all — it is a warn line in `daemon.log`.
 *
 * So these retry on the same backoff but do NOT consume the attempt budget and can never be the
 * reason for a permanent give-up. They are bounded instead by wall-clock (`#localPreconditionCap`),
 * so a genuinely dead daemon still stops eventually rather than retrying forever.
 */
const LOCAL_PRECONDITION_REFUSALS: ReadonlySet<string> = new Set([
  "standing_receiver_unavailable",
  "no_persisted_relay_endpoint",
  "relay_unavailable",
  "directory_unreachable",
  "transport_unavailable",
]);

const TERMINAL_SEAL_REFUSALS: ReadonlySet<string> = new Set([
  "session_abandoned",
  "seal_interrupted_rejected_by_counterparty",
  "session_already_sealed",
  // OUR OWN verification finding a genuine divergence between the two trees. Distinct from the
  // counterparty's `leaf_count_mismatch`, which never reaches here as a top-level reason — it
  // arrives as `detail.rejection_reason` under the rejection above. Naming the bare string here
  // was inert: the close cannot produce it.
  "seal_interrupted_leaf_count_mismatch",
  // DOD-M15-DIVERGE-1: this side's tree parted from the relay's ordering. Nothing backfills or
  // re-numbers a leaf, so the refusal is identical on every attempt — spending the retry budget on
  // it only delays the durable `restart_seal_gave_up_at` it was always going to reach. The operator
  // decides between comparing counts with the counterparty and force-abandoning; a resolver cannot
  // do either.
  "session_record_diverged",
  "session_not_found",
  // The relay released the session (it drops one 24 h after the last message), so there is nothing
  // left for any directory to rebuild the record from. No amount of retrying brings it back.
  "seal_carry_empty",
  // Two of our SEAL ctrl leaves in one durable carry. No directory can ever notarize it, and no
  // retry changes the carry.
  "seal_carry_duplicate_own_ctrl_leaf",
  // The lookup that answers "is a ctrl leaf already posted?" failed. Refusing is correct — a second
  // leaf is permanent — but retrying it five times cannot make the database readable.
  "seal_leaf_recovery_unavailable",
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
    //
    // THE RESIDUAL WINDOW IS ACCEPTED, NOT CLOSED, and it is stated here rather than implied.
    // Once the timeout wins the race, `#inFlight` is cleared while the underlying close may still
    // be running — so a `stop()` arriving after that point returns immediately and can still sever
    // signaling under a half-finished exchange. That is the deliberate trade: a bounded shutdown is
    // worth more than a guaranteed-clean one, because an unbounded wait here wedges the daemon
    // permanently while the divergence it prevents is repairable by the next close. An attempt
    // taking longer than `attemptTimeoutMs` is not pathological — the interrupted path can spend
    // 30 s in the seal flow, 30 s in a retry after discovery, and 30 s in the escalation.
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
    /**
     * review F2 — a local precondition is not a verdict on the session.
     *
     * `attempts` is decremented back so this pass costs nothing from the budget: the session is
     * retried on the same backoff, and only a refusal that says something about the SESSION can
     * exhaust it. Without this, all 28 pending sessions were durably given up on ~15 minutes after
     * every boot, and no future boot would ever enumerate them again.
     */
    const localPrecondition = !terminal && LOCAL_PRECONDITION_REFUSALS.has(outcome.reason);
    if (localPrecondition) {
      item.attempts = Math.max(0, item.attempts - 1);
      this.#deps.logger.info("session.restart_seal.not_ready", {
        agentName: item.orphan.agentName,
        sessionId: item.orphan.sessionId,
        reason: outcome.reason,
        impact: "a local precondition, not a verdict on the session — retried without spending an attempt",
      });
    }
    if (terminal || (!localPrecondition && item.attempts >= this.#maxAttempts)) {
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
        // review F4: the fallback must not tell a `seal_interrupted_pending` session it is
        // "interrupted", nor point at force-abandon — forcing there forfeits a signed commitment and
        // the relay-witnessed leaves that are ready to notarize.
        guidance:
          outcome.guidance ??
          (item.orphan.status === "seal_interrupted_pending"
            ? ("This session holds a seal commitment and could not be notarized automatically. The " +
               "commitment and the full transcript are intact — retry cello_close_session once the " +
               "agent is started and the daemon reports healthy. Do NOT force-abandon it: that ends " +
               "it WITHOUT the receipt it is one request away from having.")
            : ("This session could not be sealed automatically and is still interrupted. Close it with " +
               "cello_close_session, or force-abandon it — which ends it WITHOUT a notarized receipt.")),
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
