/**
 * DOD-M15-STALEROSTER-1 — a directory-roster reading that refuses to present itself as current.
 *
 * ─── The defect, measured twice on two machines ────────────────────────────────────────────────
 *
 * Both daemons displayed directory node failures from minutes long past while `curl` reached all
 * three nodes in 37–184 ms. The operator debugs an outage that ended before they looked.
 *
 * ─── The cause, CORRECTED after review ─────────────────────────────────────────────────────────
 *
 * This file first said the sweep had ONE caller — the failover path — and therefore ran only while
 * the daemon was unhealthy. **That is false, and a thirty-second grep falsifies it.**
 * `resolveConsortiumRoster` has ten callers: the failover resolver, four session and seal ceremony
 * handlers, the seal auto-ack broker reconnect, `cello_refresh`, `cello_get_submission_results`,
 * three cross-node session-setup paths, and the seal broker.
 *
 * The real shape is **an IDLE daemon never re-measures**. Every one of those callers is
 * activity-driven, so the reading is refreshed by ceremonies and session setup and by nothing else.
 * A daemon that sits still — which is what a daemon does between conversations — keeps the reading
 * it was seeded with at boot, for as long as it stays still. The measured symptom is that startup
 * seeded a failing reading and nothing happened afterwards to overwrite it.
 *
 * The fix is unchanged by the correction: a time-driven sweep is exactly what an activity-driven
 * producer lacks. But the wrong map had a cost — believing there was a single writer is why the
 * concurrent-sweep race below was not considered until review found it.
 *
 * ─── Two halves, because "no reading" and "an old reading" are different lies ───────────────────
 *
 * 1. `startRosterSweep` keeps measuring on a slow timer even when everything is healthy, so the
 *    reading cannot freeze.
 * 2. `classifyRosterReading` / `describeRosterFreshness` make the reading state its own age, so a
 *    sweep that has stopped (or never started) is visible rather than inferred.
 *
 * The line rules out the tempting third option: *"Do not fix it by hiding the field when stale —
 * absent and healthy must not look alike."* Suppressing a stale block trades a wrong answer for no
 * answer, and no answer renders exactly like health.
 *
 * ─── Why "no reading" is a distinct kind, and the SECOND thing review corrected ─────────────────
 *
 * This file also claimed an EXPIRED manifest reaches the unmeasured state. It does not: a daemon
 * whose manifest fails verification **refuses to start** (`daemon.ts`, ADV-002 — "an operator who
 * configures manifestProvider has opted INTO manifest enforcement"). Not-yet-valid, rollback and
 * load-failure are the same. Shipping that sentence in operator guidance sent the reader hunting a
 * manifest problem, through a log family that has no lines on the only path that can actually get
 * here. Error substitution, in brand-new prose, inside the fix for error substitution.
 *
 * The one reachable route is **no manifest provider at all**, and it is DESIGNED and BENIGN:
 * `manifest-deps.ts` returns `{}` when `CELLO_DIRECTORY_URL` is not byte-equal to a bundled
 * endpoint — local dev, the e2e harness, or an operator who used a DNS hostname for a bundled node.
 * So it gets its own kind and its own calm wording. Treating it as an alarm would fire on every
 * local run and every harness spin-up: a signal on the designed normal case, which this same file
 * forbids two paragraphs down.
 *
 * Both kinds still EMIT — the line rules out hiding the field, because absent and healthy must not
 * look alike. What changes between them is what the operator is told to do about it.
 */

/**
 * How old a reading may be before it stops claiming the present tense.
 *
 * Five minutes is chosen against the SWEEP interval, not against operator patience: the sweep is
 * slow by design (it probes every node in the consortium), so the bound has to be comfortably
 * longer than one sweep period or a healthy daemon would flap between fresh and stale between
 * ticks. It is the answer to "could this have changed without us noticing", and at five minutes the
 * answer is still usually no.
 */
export const ROSTER_STALE_AFTER_MS = 5 * 60_000;

/** How often the background sweep re-measures. Comfortably inside `ROSTER_STALE_AFTER_MS`. */
export const ROSTER_SWEEP_INTERVAL_MS = 90_000;

export type RosterReading =
  | { kind: "never_measured" }
  | { kind: "fresh"; sweptAt: string; ageMs: number }
  | { kind: "stale"; sweptAt: string; ageMs: number };

/**
 * How old is this reading, and may it still speak in the present tense?
 *
 * Pure and clock-injected: `nowMs` is a parameter so the boundary can be tested exactly rather than
 * approximately, and so a test never has to sleep.
 */
export function classifyRosterReading(
  sweptAt: string | null,
  nowMs: number,
  staleAfterMs: number = ROSTER_STALE_AFTER_MS,
): RosterReading {
  // No measurement at all — a different fact from an old measurement, and the only one that can
  // hide an expired manifest. See the header.
  if (sweptAt === null) return { kind: "never_measured" };

  const takenMs = Date.parse(sweptAt);
  // An unparseable timestamp is a reading whose age cannot be established. FRESH is the one answer
  // that must never be reachable by accident — it is the claim that costs the operator an
  // investigation — so anything unmeasurable falls to stale.
  if (Number.isNaN(takenMs)) return { kind: "stale", sweptAt, ageMs: Number.NaN };

  const ageMs = nowMs - takenMs;
  // A reading from the FUTURE is not infinitely fresh. Clock skew, a restored snapshot or an
  // operator moving the system clock would otherwise satisfy the freshness bound forever — the
  // freeze this whole unit exists to end, arriving by a different door.
  if (ageMs < 0) return { kind: "stale", sweptAt, ageMs };

  return ageMs > staleAfterMs ? { kind: "stale", sweptAt, ageMs } : { kind: "fresh", sweptAt, ageMs };
}

export interface RosterFreshness {
  /** ISO timestamp of the reading, or null when nothing has ever been measured. */
  checked_at: string | null;
  /** Whole seconds since the reading, or null when there is no reading (or its age is unknowable). */
  age_seconds: number | null;
  /** True when this reading must not be read as the present tense. */
  stale: boolean;
  /**
   * WHICH of the non-current states this is, because they call for different responses:
   *   `current`         — measured recently; the only state that may speak in the present tense.
   *   `stale`           — measured, too long ago to be trusted as now.
   *   `never`           — a manifest IS configured but no sweep has completed yet.
   *   `not_configured`  — no consortium manifest, so there is no roster to measure. DESIGNED.
   */
  measurement: "current" | "stale" | "never" | "not_configured";
  /** Present ONLY when the reading is not current — a flag on every reading is not a flag. */
  freshness_guidance?: string;
  /**
   * The last sweep failure, when the background sweep is erroring — DOD-M15-STALEROSTER-1 review F4.
   *
   * The log alone was not enough: a sweep failing every 90–180 s leaves the reading inside its
   * 5-minute freshness bound for the first two or three failures, so the block reports
   * `stale: false` and hands over a frozen reading as current. That is the defect this whole line
   * exists to end, arriving through the new code's own failure path. The agent response carries the
   * cause, and the log line stays.
   */
  last_sweep_error?: { event: string; error: string; at: string; consecutive: number };
}

/**
 * Render a reading's age for an operator-facing response.
 *
 * A FRESH reading is deliberately left undecorated. A staleness marker attached to every reading
 * fires on the ordinary case, which is the failure this milestone keeps re-finding: it is not a
 * signal, and it teaches the reader to skip past the one that is real.
 */
export function describeRosterFreshness(
  reading: RosterReading,
  opts: { manifestConfigured: boolean; lastSweepError?: RosterFreshness["last_sweep_error"] } = {
    manifestConfigured: true,
  },
): RosterFreshness {
  const errorField = opts.lastSweepError ? { last_sweep_error: opts.lastSweepError } : {};

  if (reading.kind === "never_measured") {
    // DESIGNED AND BENIGN — the calm branch. Firing an alarm here would fire it on every local-dev
    // daemon and every e2e-harness spin-up, which is a signal on the normal case.
    if (!opts.manifestConfigured) {
      return {
        checked_at: null,
        age_seconds: null,
        stale: false,
        measurement: "not_configured",
        freshness_guidance:
          "Directory reachability is NOT MEASURED on this daemon because no consortium manifest is " +
          "configured, so there is no node roster to probe. This is expected in local development " +
          "and in the e2e harness. It also happens against a real directory when " +
          "CELLO_DIRECTORY_URL is not byte-equal to a bundled endpoint — a DNS hostname for a " +
          "bundled node does NOT match, and turns this off along with directory identity " +
          "authentication. Look for daemon.manifest.bundled.skipped in the log; if it is there with " +
          "a non-local URL, this client is weaker than you think it is. The empty node list below " +
          "is the absence of a measurement, not a clean bill of health.",
        ...errorField,
      };
    }
    return {
      checked_at: null,
      age_seconds: null,
      stale: true,
      measurement: "never",
      freshness_guidance:
        "A consortium manifest IS configured, but no directory-reachability sweep has completed " +
        "yet, so the absence of failures below is not evidence of health — nothing has finished " +
        "looking. Immediately after startup this is normal and resolves within a couple of minutes. " +
        "If it persists, the background sweep is not completing: look for " +
        "directory.roster.sweep.failed in the log, and see last_sweep_error here if it is present.",
      ...errorField,
    };
  }

  if (reading.kind === "fresh") {
    return {
      checked_at: reading.sweptAt,
      age_seconds: Math.floor(reading.ageMs / 1000),
      stale: false,
      measurement: "current",
      ...errorField,
    };
  }

  const ageKnown = Number.isFinite(reading.ageMs) && reading.ageMs >= 0;
  return {
    checked_at: reading.sweptAt,
    age_seconds: ageKnown ? Math.floor(reading.ageMs / 1000) : null,
    stale: true,
    measurement: "stale",
    freshness_guidance:
      (ageKnown
        ? `This reading is ${Math.floor(reading.ageMs / 1000)} seconds old. `
        : `This reading's age could not be established (checked_at is ${
            Number.isNaN(reading.ageMs) ? "unparseable" : "in the future — check the system clock"
          }). `) +
      "Anything reported below MAY NO LONGER BE TRUE: the nodes listed may already have recovered. " +
      "Do not begin an investigation from it — this has been measured twice, on two machines, where " +
      "a daemon showed node failures from minutes past while all three nodes answered in under " +
      "200 ms. " +
      // REVIEW F12: the first draft said "the background sweep has stopped; look for
      // directory.roster.sweep.failed" — but the likeliest cause by far is a laptop that slept,
      // where the sweep did not FAIL, it did not RUN, and that log line will not be there. Sending
      // the operator to look for a line that cannot exist is the same substitution as F1, smaller.
      "The sweep did not complete on schedule. Two causes: the process was suspended (a laptop " +
      "asleep is the common one, and needs nothing — the next sweep corrects it), or the sweep is " +
      "erroring, in which case last_sweep_error appears above and directory.roster.sweep.failed is " +
      "in the log.",
    ...errorField,
  };
}

/** Minimal structural logger — `domain.noun.verb` taxonomy, injected, never imported. */
export interface RosterSweepLogger {
  info(event: string, ctx?: Record<string, unknown>): void;
  warn(event: string, ctx?: Record<string, unknown>): void;
  error(event: string, ctx?: Record<string, unknown>): void;
}

export interface RosterSweepScheduler {
  scheduleNext(callbackFn: () => Promise<void>): void;
  cancel(): void;
}

/**
 * Keep measuring directory reachability on a slow timer, whether or not anything is broken.
 *
 * This is the half that actually fixes the freeze: every existing caller of the sweep is
 * activity-driven (ceremonies, session setup, `cello_refresh`), so an IDLE daemon never
 * re-measures — and sitting idle is what a daemon does between conversations. A time-driven sweep
 * is precisely what an activity-driven producer lacks.
 *
 * Mirrors `startHttpManifestPoll`'s shape deliberately — same re-arm discipline, same
 * never-throw-out-of-the-tick rule, same stop function.
 */
export function startRosterSweep(opts: {
  scheduler: RosterSweepScheduler;
  sweep: () => Promise<unknown>;
  logger: RosterSweepLogger;
  /**
   * REVIEW F4 — where a sweep failure becomes visible to the AGENT, not only to the log.
   *
   * Invariant 2 asks for both, and the log alone was measurably not enough here: the freshness
   * bound is five minutes and the sweep runs every 90–180 s, so the first two or three consecutive
   * failures all land while the reading still reports `stale: false`. The operator is handed a
   * frozen reading presented as current — this line's own defect, arriving through the fix's
   * failure path. The bound that prevents flapping is the same window that blinds it.
   */
  onSweepError?: (e: NonNullable<RosterFreshness["last_sweep_error"]>) => void;
  onSweepSuccess?: () => void;
  now?: () => number;
}): () => void {
  const { scheduler, sweep, logger, onSweepError, onSweepSuccess, now = Date.now } = opts;
  let stopped = false;
  let consecutive = 0;

  const tick = async (): Promise<void> => {
    if (stopped) return;
    try {
      await sweep();
      /**
       * RE-CHECK AFTER THE AWAIT — review F10, partial.
       *
       * A sweep takes up to ~16 s with a node down, so a `stop()` landing mid-sweep is ordinary,
       * not exotic. Without this the completing sweep still fires its callbacks and still logs,
       * against a daemon that has already reported itself stopped — which in-process means writing
       * through a logger whose test has finished, and in production means status side effects after
       * teardown.
       *
       * This does NOT abort the outbound probes: `fetchBootstrapResult` owns a per-request
       * AbortController for its own deadline and takes no external signal, so cancelling them means
       * threading one through `manifestNodesToEndpoints`. Carried as
       * `DOD-M15-SWEEP-ABORT-1` rather than done here — the probes are read-only GETs against
       * `/bootstrap` and the process is exiting; what mattered was not acting on the result.
       */
      if (stopped) return;
      consecutive = 0;
      onSweepSuccess?.();
    } catch (err: unknown) {
      if (stopped) return;
      consecutive++;
      onSweepError?.({
        event: "directory.roster.sweep.failed",
        error: err instanceof Error ? err.message : String(err),
        at: new Date(now()).toISOString(),
        consecutive,
      });
      /**
       * LOUD, and then RE-ARMED. Swallowing this would leave the reading frozen with nothing
       * saying measurement had stopped — the original defect, silently reintroduced. Skipping the
       * re-arm would do the same thing more permanently: one bad probe and the clock stops for the
       * life of the process.
       *
       * The upstream cause is carried into the log rather than replaced with a label, because
       * "the sweep failed" does not tell an operator whether their resolver is down, their network
       * is gone, or a node is refusing them.
       */
      logger.error("directory.roster.sweep.failed", {
        error: err instanceof Error ? err.message : String(err),
        impact:
          "directory reachability was not re-measured this cycle, so cello_status is answering " +
          "from an older reading. It will say so: a reading past its bound reports stale:true.",
        guidance:
          "If this repeats, the roster reading in cello_status cannot be trusted as current — " +
          "check DNS resolution for the directory endpoints from this machine.",
      });
    }
    // OUTSIDE the try. A re-arm that lives in the success path is how a sweep stops forever.
    if (!stopped) scheduler.scheduleNext(tick);
  };

  scheduler.scheduleNext(tick);
  return () => {
    stopped = true;
    scheduler.cancel();
  };
}
