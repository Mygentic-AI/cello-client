/**
 * DOD-M15-MANIFEST-EXPIRY-LIVE-1 — a running daemon notices its own trust anchor expiring.
 *
 * ─── The gap ───────────────────────────────────────────────────────────────────────────────────
 *
 * The consortium manifest's validity window is enforced in exactly one place — `verifyStartupManifest`,
 * at boot. After that **nothing looks at it again for the life of the process.**
 *
 * There is a second expiry check, and it is the reason this went unnoticed: `http-manifest-poll.ts`
 * refuses to ADOPT a manifest that has expired. That checks the manifest being fetched, never the
 * one already held — so a daemon whose anchor has lapsed keeps polling, keeps correctly refusing
 * expired replacements, and keeps using the expired anchor it already has. The check that exists
 * reads, at a glance, as if this were covered.
 *
 * On the PRODUCTION DEFAULT it is worse: the bundled-manifest path wires no poll scheduler at all
 * ("the bundled roster is static"), so there is not even a fetch that might have noticed.
 *
 * ─── Why it matters, concretely ────────────────────────────────────────────────────────────────
 *
 * The manifest is the trust anchor for directory identity authentication (step 6) and for the node
 * roster a threshold ceremony draws from. The expiry is not bookkeeping: past it those signatures no
 * longer warrant the CURRENT consortium, so a node removed for cause remains trusted — silently, by
 * a daemon that believes it is enforcing.
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
 * A daemon does NOT tear itself down at the expiry instant. Startup fails closed, which is the right
 * place to refuse. Killing a live daemon on a wall-clock boundary trades slow security decay for
 * immediate total unavailability — and does it to every operator at once, since they share the
 * bundled manifest's date, turning a rotation slip into a fleet-wide outage mid-conversation.
 * Runtime's job is to say so loudly, in the log AND in the response, early enough to act.
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
  warningMs: number = MANIFEST_EXPIRY_WARNING_MS,
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

  const notBeforeMs = Date.parse(manifest.not_before);
  if (!Number.isNaN(notBeforeMs) && nowMs < notBeforeMs) {
    return { state: "not_yet_valid", notBefore: manifest.not_before };
  }

  if (expiresMs <= nowMs) {
    return { state: "expired", expires: manifest.expires, secondsSince: Math.floor((nowMs - expiresMs) / 1000) };
  }

  const remainingMs = expiresMs - nowMs;
  const secondsRemaining = Math.floor(remainingMs / 1000);
  return remainingMs <= warningMs
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
export function describeManifestValidity(v: ManifestValidity): Record<string, unknown> | undefined {
  if (v.state === "valid" || v.state === "not_configured") return undefined;

  if (v.state === "not_yet_valid") {
    return {
      manifest_expired: false,
      manifest_not_yet_valid: true,
      manifest_valid_from: v.notBefore,
      manifest_validity_guidance:
        `The consortium manifest does not become valid until ${v.notBefore}, and this daemon is ` +
        "still running against it. Either this machine's clock is wrong — the common cause, and the " +
        "one to check first — or a manifest was rotated in ahead of its window.",
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
        "start, which is how this usually gets discovered, at the worst moment.",
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
      "anchor that has lapsed: a node removed from the consortium since then is still trusted here. " +
      "Rotate the manifest. Do NOT simply restart to clear this — a restart will REFUSE to start " +
      "(startup fails closed on an expired manifest), so restarting without a fresh manifest turns " +
      "a degraded daemon into a dead one.",
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
  warningMs?: number;
}): () => ManifestValidity {
  const { getManifest, logger, now = Date.now, warningMs = MANIFEST_EXPIRY_WARNING_MS } = opts;
  let lastReported: string | null = null;

  return (): ManifestValidity => {
    const v = classifyManifestValidity(getManifest(), now(), warningMs);
    const key =
      v.state === "not_configured" ? "not_configured"
      : v.state === "not_yet_valid" ? `not_yet_valid:${v.notBefore}`
      : `${v.state}:${v.expires}`;

    if (key === lastReported) return v;
    lastReported = key;

    if (v.state === "expired") {
      logger.error("directory.auth.manifest.expired.live", {
        expiresAt: v.expires,
        expiredDaysAgo: Math.floor(v.secondsSince / 86_400),
        impact:
          "the daemon is STILL RUNNING on this manifest. Directory identity authentication and the " +
          "threshold-ceremony roster are drawn from an anchor whose signatures no longer warrant " +
          "the current consortium — a node removed since then is still trusted.",
        guidance:
          "Rotate the manifest. Do not restart to clear it: startup fails closed on an expired " +
          "manifest, so a restart without a fresh one turns a degraded daemon into a dead one.",
      });
    } else if (v.state === "expiring_soon") {
      logger.warn("directory.auth.manifest.expiring", {
        expiresAt: v.expires,
        daysRemaining: Math.floor(v.secondsRemaining / 86_400),
        impact: "after this date the daemon keeps running on the expired manifest rather than failing closed.",
        guidance: "Rotate before the date. A daemon RESTARTED after it will refuse to start.",
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
