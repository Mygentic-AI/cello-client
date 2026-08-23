/**
 * DOD-M15-MANIFEST-EXPIRY-LIVE-1 — a running daemon notices its own trust anchor expiring.
 *
 * ─── The gap ───────────────────────────────────────────────────────────────────────────────────
 *
 The consortium manifest's validity window is enforced at boot (`verifyStartupManifest`) and, after
 * that, in exactly ONE consumer: `signal-submission.ts` re-checks the HELD manifest at request time
 * and refuses. Nothing else does — not directory identity authentication, not the ceremony roster.
 *
 * (An earlier version of this header said nothing re-checked the held manifest at all. That was
 * wrong — the third false claim I have shipped in three units — and the correction matters, because
 * the real shape is not "unchecked" but INCONSISTENT: the daemon refuses the lowest-stakes consumer
 * and permits the two highest-stakes ones, invisibly. See the decision note below.)
 *
 * There is also a check that reads like coverage and is not: `http-manifest-poll.ts` refuses to
 * ADOPT an expired manifest. That checks the manifest being FETCHED, never the one already held — so
 * a daemon whose anchor has lapsed keeps polling, keeps correctly refusing expired replacements, and
 * keeps using the expired anchor it already has.
 *
 * On the PRODUCTION DEFAULT it is worse: the bundled-manifest path wires no poll scheduler at all
 * ("the bundled roster is static"), so there is not even a fetch that might have noticed.
 *
 * ─── Why it matters, concretely ────────────────────────────────────────────────────────────────
 *
 The manifest is the trust anchor for directory identity authentication (step 6) and for the node
 * roster a threshold ceremony draws from — both re-read `getCurrentManifest()` at request time, so
 * both genuinely run on whatever is held.
 *
 * What expiry means precisely (review F10, correcting my own overstatement): it is the NOTICE that
 * the anchor may be out of date, not the mechanism by which it becomes so. The daemon trusts the
 * identical roster the day BEFORE expiry; what keeps a removed node trusted is never having adopted
 * v+1. So the accurate statement is that past expiry there is NO ASSURANCE the enforced roster is
 * current — a node removed since then would still be trusted, and nothing here can say whether one
 * was.
 *
 * ─── Found the wrong way round ─────────────────────────────────────────────────────────────────
 *
 * `DOD-M15-STALEROSTER-1` shipped a guidance string blaming an expired manifest for a state an
 * expired manifest cannot reach (that daemon refuses to start). Review corrected it and pointed at
 * where the hazard actually lives — here. After that unit, a daemon in this state reports its roster
 * reading as `stale: false`: a confidently fresh measurement taken against a dead anchor, which is
 * worse than the stale reading that line existed to fix.
 *
 * ─── Decision: report, do not kill ─────────────────────────────────────────────────────────────
 *
 A daemon does NOT tear itself down at the expiry instant. §2b invariant 2 backs this explicitly —
 * *"Loud does not mean blocking… treating every failure as fatal is its own defect."*
 *
 * But review corrected the FRAMING, and the correction is worth keeping: the availability argument I
 * originally made does not survive. The fleet-wide stop I claimed to be avoiding happens anyway, at
 * each operator's next restart, via ADV-002 — report-only DEFERS that outage, it does not prevent
 * it. The honest reason to warn rather than kill is that a wall-clock boundary is a bad trigger for
 * tearing down live conversations, not that it avoids the outage.
 *
 * The real question was never global report-vs-kill; it is PER CONSUMER, and the repo has already
 * ruled on one of them inconsistently. `signal-submission.ts` refuses a trust-signal submission on
 * expiry, while `register-handler.ts` deals a FROST share against a roster re-resolved from the same
 * lapsed manifest with no gate, and the challenge verifier authenticates a directory against it with
 * no gate. **The daemon refuses its lowest-stakes consumer and permits its two highest-stakes ones.**
 * That is not defended anywhere; it is carried as `DOD-M15-EXPIRY-CONSUMER-POLICY-1` rather than
 * settled inside a reporting unit.
 */

import type { ConsortiumManifest } from "@cello-protocol/protocol-types";

/**
 * How long before expiry the warning starts.
 *
 * Warning at the expiry instant is useless — the operator finds out once they are already running
 * on a dead anchor. Seven days is chosen to cover a weekend plus the working days either side, which
 * is the realistic floor for noticing an alert and rotating a threshold-signed artefact.
 */
export const MANIFEST_EXPIRY_WARNING_MS = 7 * 86_400_000;

export type ManifestValidity =
  | { state: "not_configured" }
  | { state: "not_yet_valid"; notBefore: string }
  /**
   * The window itself is unreadable — a `not_before` that does not parse.
   *
   * Its OWN state, deliberately not folded into `expired`: those need different words. "Expired"
   * tells an operator to rotate a manifest that is stale; this tells them a field in the manifest is
   * GARBAGE, which is a different problem with a different fix and is more likely to mean the
   * artefact was hand-edited or produced by a broken generator.
   */
  | { state: "unreadable_window"; notBefore: string }
  | { state: "valid"; expires: string; secondsRemaining: number }
  | { state: "expiring_soon"; expires: string; secondsRemaining: number }
  | { state: "expired"; expires: string; secondsSince: number };

/**
 * Where does this manifest sit in its validity window, as of `nowMs`?
 *
 * Clock injected so the boundaries are tested exactly rather than approximately.
 */
export function classifyManifestValidity(
  manifest: Pick<ConsortiumManifest, "not_before" | "expires"> | null | undefined,
  nowMs: number,
): ManifestValidity {
  if (!manifest) return { state: "not_configured" };

  const expiresMs = Date.parse(manifest.expires);
  /**
   * AN UNREADABLE EXPIRY IS EXPIRED.
   *
   * `new Date("nonsense") <= now` is FALSE — every comparison against NaN is false — so the
   * startup check's own shape waves a garbage timestamp through as though it were in-window. Valid
   * is the answer that costs security here, so nothing unmeasurable may reach it.
   */
  if (Number.isNaN(expiresMs)) return { state: "expired", expires: manifest.expires, secondsSince: 0 };

  /**
   * AN UNREADABLE `not_before` FAILS CLOSED TOO — review F3, and it was my own defect sitting
   * directly under the comment above claiming it could not happen.
   *
   * The first cut wrote `if (!Number.isNaN(notBeforeMs) && nowMs < notBeforeMs)`, which SKIPS the
   * window-open check entirely when the field is garbage and falls through to a possible `valid`.
   * So `not_before: "2026-13-01T00:00:00Z"` — month thirteen, the shape a hand-edited or
   * generator-bugged artefact actually has — classified as valid, contributed nothing to the status
   * surface, and logged nothing. I handled the same case correctly for `expires` eleven lines up and
   * then wrote the inverted guard for `not_before`, under a comment asserting the property.
   *
   * `signal-submission.ts` already had this right (`!Number.isFinite(expiresAt) || expiresAt <= now`)
   * and is the precedent.
   */
  const notBeforeMs = Date.parse(manifest.not_before);
  if (Number.isNaN(notBeforeMs)) {
    return { state: "unreadable_window", notBefore: manifest.not_before };
  }
  if (nowMs < notBeforeMs) {
    return { state: "not_yet_valid", notBefore: manifest.not_before };
  }

  if (expiresMs <= nowMs) {
    return { state: "expired", expires: manifest.expires, secondsSince: Math.floor((nowMs - expiresMs) / 1000) };
  }

  const remainingMs = expiresMs - nowMs;
  const secondsRemaining = Math.floor(remainingMs / 1000);
  // The constant directly, not an injectable parameter — review F9. A `warningMs` argument had no
  // caller anywhere, and it was the ONE seam by which the two surfaces could ever disagree: the
  // status path could not pass a custom window while the watch could. An unused knob whose only
  // possible effect is drift between two readings of the same fact.
  return remainingMs <= MANIFEST_EXPIRY_WARNING_MS
    ? { state: "expiring_soon", expires: manifest.expires, secondsRemaining }
    : { state: "valid", expires: manifest.expires, secondsRemaining };
}

/**
 * The operator-facing fields for `cello_status`, or `undefined` when there is nothing to say.
 *
 * A healthy manifest contributes NOTHING. A field that is present on every status read for the
 * years a manifest is valid is not a warning — it is furniture, and it teaches the reader to skip
 * the block that matters. This is the finding this milestone has produced more often than any other.
 */
/**
 * WHERE the manifest came from, because it decides what the remedy even IS — review F5.
 *
 * `bundled` is a compiled-in constant: there is no file to replace and no poll to adopt a
 * replacement, so "rotate the manifest" is not an action that operator can take. Telling them to do
 * it anyway is worse than unhelpful, because the workaround they will reach for — repointing
 * `CELLO_DIRECTORY_URL` at something not byte-equal to a bundled endpoint — makes `buildManifestDeps`
 * return nothing, which starts the daemon with directory identity authentication SILENTLY OFF.
 * Guidance that routes a stuck operator toward disabling a security control is a defect in the
 * guidance.
 */
export type ManifestOrigin = "bundled" | "file";

/** What to actually DO about a manifest that needs replacing, given where it came from. */
function remedyFor(origin: ManifestOrigin): string {
  return origin === "bundled"
    ? "This daemon uses the COMPILED-IN consortium manifest, so there is no file to replace: " +
      "upgrade the @cello-protocol/connect package to get a newer one. Do NOT repoint " +
      "CELLO_DIRECTORY_URL to get past this — an endpoint that is not byte-equal to a bundled one " +
      "makes the daemon start with directory identity authentication switched off, which is a " +
      "weaker client than the one you are trying to fix."
    : "Replace the manifest file at CELLO_CONSORTIUM_MANIFEST with a current one.";
}

export function describeManifestValidity(
  v: ManifestValidity,
  origin: ManifestOrigin = "file",
): Record<string, unknown> | undefined {
  if (v.state === "valid" || v.state === "not_configured") return undefined;

  if (v.state === "unreadable_window") {
    return {
      manifest_expired: false,
      manifest_window_unreadable: true,
      manifest_valid_from: v.notBefore,
      manifest_validity_guidance:
        `The consortium manifest's not_before field cannot be parsed as a date (got ` +
        `${JSON.stringify(v.notBefore)}), so this daemon cannot tell whether its trust anchor's ` +
        "validity window has even opened. This is a MALFORMED manifest rather than a stale one — " +
        "the usual causes are a hand-edited file or a broken generator. " + remedyFor(origin),
    };
  }

  if (v.state === "not_yet_valid") {
    return {
      manifest_expired: false,
      manifest_not_yet_valid: true,
      manifest_valid_from: v.notBefore,
      manifest_validity_guidance:
        `The consortium manifest does not become valid until ${v.notBefore}, and this daemon is ` +
        "still running against it. Either this machine's clock is wrong — the common cause, and the " +
        "one to check first — or a manifest was rotated in ahead of its window. " + remedyFor(origin),
    };
  }

  if (v.state === "expiring_soon") {
    const days = Math.floor(v.secondsRemaining / 86_400);
    return {
      manifest_expired: false,
      manifest_expires_at: v.expires,
      manifest_expires_in_days: days,
      manifest_validity_guidance:
        `The consortium manifest expires in ${days} day(s), at ${v.expires}. Rotate it before then. ` +
        "After expiry this daemon KEEPS RUNNING on the old manifest — it does not fail closed the " +
        "way startup does — so nothing will stop working at the deadline and nothing will announce " +
        "it except this field and one log line. A daemon RESTARTED after expiry will refuse to " +
        "start, which is how this usually gets discovered, at the worst moment. " + remedyFor(origin),
    };
  }

  const days = Math.floor(v.secondsSince / 86_400);
  return {
    manifest_expired: true,
    manifest_expires_at: v.expires,
    manifest_expired_days_ago: days,
    manifest_validity_guidance:
      `The consortium manifest EXPIRED at ${v.expires} (${days} day(s) ago) and this daemon is ` +
      "still running on it. Its signatures no longer warrant the current consortium, so directory " +
      "identity authentication and the threshold-ceremony roster are both being drawn from an " +
      "anchor that has lapsed, so this daemon has NO ASSURANCE that the roster it enforces is the " +
      "current one. A node removed from the consortium since then would still be trusted here, and " +
      "nothing in this daemon can tell you whether one was. " + remedyFor(origin) + " Do NOT simply " +
      "restart to clear this — a restart will REFUSE to start (startup fails closed on an expired " +
      "manifest), so restarting without a fresh manifest turns a degraded daemon into a dead one.",
  };
}

/** Minimal structural logger — `domain.noun.verb` taxonomy, injected. */
export interface ManifestValidityLogger {
  info(event: string, ctx?: Record<string, unknown>): void;
  warn(event: string, ctx?: Record<string, unknown>): void;
  error(event: string, ctx?: Record<string, unknown>): void;
}

/**
 * A check to call periodically, which logs each TRANSITION once.
 *
 * Returns a function rather than owning a timer: the roster sweep already ticks every 90–180 s on
 * exactly the path where a manifest provider exists, so this rides it. A second timer measuring the
 * same subsystem would be two things to stop, two things to test, and two places for the interval
 * to drift out of agreement with the freshness bound.
 *
 * The latch is keyed on the STATE PLUS the expiry string, so rotating the manifest re-arms it. A
 * bare boolean would mean an operator who rotated once could never be warned again — the warning
 * would have been spent on a manifest that is no longer installed.
 */
export function startManifestValidityWatch(opts: {
  getManifest: () => Pick<ConsortiumManifest, "not_before" | "expires"> | null | undefined;
  logger: ManifestValidityLogger;
  now?: () => number;
}): () => ManifestValidity {
  const { getManifest, logger, now = Date.now } = opts;
  let lastReported: string | null = null;

  return (): ManifestValidity => {
    const v = classifyManifestValidity(getManifest(), now());
    const key =
      v.state === "not_configured" ? "not_configured"
      : v.state === "not_yet_valid" || v.state === "unreadable_window" ? `${v.state}:${v.notBefore}`
      : `${v.state}:${v.expires}`;

    if (key === lastReported) return v;
    lastReported = key;

    if (v.state === "expired") {
      logger.error("directory.auth.manifest.expired.live", {
        expiresAt: v.expires,
        expiredDaysAgo: Math.floor(v.secondsSince / 86_400),
        impact:
          "the daemon is STILL RUNNING on this manifest. Directory identity authentication and the " +
          "threshold-ceremony roster are drawn from it at request time, so there is NO ASSURANCE " +
          "the enforced roster is the current one — a node removed since then would still be " +
          "trusted, and nothing here can say whether one was.",
        guidance:
          "Replace the manifest (a file at CELLO_CONSORTIUM_MANIFEST, or an @cello-protocol/connect " +
          "upgrade if this daemon uses the compiled-in one). Do not restart to clear it: startup " +
          "fails closed on an expired manifest, so a restart without a fresh one turns a degraded " +
          "daemon into a dead one.",
      });
    } else if (v.state === "expiring_soon") {
      logger.warn("directory.auth.manifest.expiring", {
        expiresAt: v.expires,
        daysRemaining: Math.floor(v.secondsRemaining / 86_400),
        impact: "after this date the daemon keeps running on the expired manifest rather than failing closed.",
        guidance: "Rotate before the date. A daemon RESTARTED after it will refuse to start.",
      });
    } else if (v.state === "unreadable_window") {
      logger.error("directory.auth.manifest.window.unreadable", {
        notBefore: v.notBefore,
        impact:
          "the manifest's not_before field does not parse as a date, so this daemon cannot tell " +
          "whether its trust anchor's validity window has opened. It is running against it anyway.",
        guidance: "The manifest is MALFORMED, not stale — a hand-edited file or a broken generator. Replace it.",
      });
    } else if (v.state === "not_yet_valid") {
      logger.error("directory.auth.manifest.not.yet.valid.live", {
        notBefore: v.notBefore,
        impact: "the daemon is running against a manifest whose validity window has not opened.",
        guidance: "Check this machine's clock first — that is the common cause.",
      });
    }
    return v;
  };
}
