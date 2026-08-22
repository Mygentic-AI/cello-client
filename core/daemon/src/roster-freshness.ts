/**
 * DOD-M15-STALEROSTER-1 — a directory-roster reading that refuses to present itself as current.
 *
 * ─── The defect, measured twice on two machines ────────────────────────────────────────────────
 *
 * Both daemons displayed directory node failures from minutes long past while `curl` reached all
 * three nodes in 37–184 ms. The operator debugs an outage that ended before they looked.
 *
 * The cause is a producer with one caller. `resolveConsortiumRoster` is the only writer of the
 * unresolved-node list, and the only thing that calls it is the roster-aware endpoint resolver —
 * i.e. the FAILOVER path. So the sweep runs only while the daemon is unhealthy. The moment the
 * primary resolves again the failover path stops being taken, nothing sweeps, and the last failing
 * measurement becomes permanent for the life of the process.
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
 * ─── Why `never_measured` is a distinct kind and not just a very old reading ────────────────────
 *
 * `verifyStartupManifest` returns WITHOUT sweeping on four paths: no manifest configured, a
 * manifest that is not yet valid, an EXPIRED manifest, and a version rollback. In every one of them
 * the failure list is empty, so the status block was omitted and the daemon reported no directory
 * trouble at all. A daemon whose consortium manifest has expired is not healthy, and it was
 * indistinguishable from a daemon whose three nodes had just answered.
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
  /** Present ONLY when stale — a flag on every reading is not a flag. */
  freshness_guidance?: string;
}

/**
 * Render a reading's age for an operator-facing response.
 *
 * A FRESH reading is deliberately left undecorated. A staleness marker attached to every reading
 * fires on the ordinary case, which is the failure this milestone keeps re-finding: it is not a
 * signal, and it teaches the reader to skip past the one that is real.
 */
export function describeRosterFreshness(reading: RosterReading): RosterFreshness {
  if (reading.kind === "never_measured") {
    return {
      checked_at: null,
      age_seconds: null,
      stale: true,
      freshness_guidance:
        "This daemon has NEVER measured directory reachability, so the absence of failures below " +
        "is not evidence of health — nothing has looked. The startup manifest gate returns without " +
        "sweeping when no consortium manifest is configured, when the manifest is not yet valid, " +
        "when it has EXPIRED, or when it was rolled back; check the daemon log for " +
        "directory.auth.manifest.* at startup. An expired manifest is the common cause and does " +
        "not announce itself here.",
    };
  }

  if (reading.kind === "fresh") {
    return {
      checked_at: reading.sweptAt,
      age_seconds: Math.floor(reading.ageMs / 1000),
      stale: false,
    };
  }

  const ageKnown = Number.isFinite(reading.ageMs) && reading.ageMs >= 0;
  return {
    checked_at: reading.sweptAt,
    age_seconds: ageKnown ? Math.floor(reading.ageMs / 1000) : null,
    stale: true,
    freshness_guidance:
      (ageKnown
        ? `This reading is ${Math.floor(reading.ageMs / 1000)} seconds old. `
        : `This reading's age could not be established (checked_at is ${
            Number.isNaN(reading.ageMs) ? "unparseable" : "in the future — check the system clock"
          }). `) +
      "Anything reported below MAY NO LONGER BE TRUE: the nodes listed may already have recovered. " +
      "Do not begin an investigation from it — this has been measured twice, on two machines, where " +
      "a daemon showed node failures from minutes past while all three nodes answered in under " +
      "200 ms. A reading this old usually means the background sweep has stopped; look for " +
      "directory.roster.sweep.failed in the daemon log.",
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
 * This is the half that actually fixes the freeze: before it, the sweep's only caller was the
 * failover path, so recovering from an outage was precisely what stopped the daemon from ever
 * noticing it had recovered.
 *
 * Mirrors `startHttpManifestPoll`'s shape deliberately — same re-arm discipline, same
 * never-throw-out-of-the-tick rule, same stop function.
 */
export function startRosterSweep(opts: {
  scheduler: RosterSweepScheduler;
  sweep: () => Promise<unknown>;
  logger: RosterSweepLogger;
}): () => void {
  const { scheduler, sweep, logger } = opts;
  let stopped = false;

  const tick = async (): Promise<void> => {
    if (stopped) return;
    try {
      await sweep();
    } catch (err: unknown) {
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
