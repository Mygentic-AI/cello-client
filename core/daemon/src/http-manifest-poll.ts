/**
 * CELLO-M7-CONN-001 (DOD-CONN-3) — HTTP consortium-manifest poll.
 *
 * The manifest poll is the ONE daemon-level directory operation. With the keystone
 * deleted there is no shared authenticated signaling stream to carry it, so it moves
 * to unauthenticated HTTP: GET ${directoryUrl}/manifest. The manifest is PUBLIC,
 * self-authenticating data — threshold-signed by officer root keys that the daemon has
 * pinned LOCALLY (CELLO_CONSORTIUM_ROOT_KEYS). The directory is ONLY a transport, never
 * a trust anchor: a rogue/compromised directory cannot make us adopt a forged, expired,
 * not-yet-valid, or rolled-back manifest. The verify-before-adopt policy here is the
 * SAME TUF policy the deleted keystone signaling path enforced (SignalingManager
 * .handleManifestPollResponse), preserved unchanged across the transport move.
 *
 * Runs daemon-level — even with ZERO agents (the property the keystone, which borrowed
 * the primary agent's identity to authenticate, could never provide).
 *
 * Crypto reference: RFC 8032 (Ed25519 threshold verification via verifyManifest).
 */

import { verifyManifest, type ConsortiumManifestInput } from "@cello-protocol/crypto";
import type { ConsortiumManifest } from "@cello-protocol/protocol-types";
import type { IManifestProvider, IManifestVersionStore, IManifestPollScheduler } from "@cello-protocol/transport";

/** Minimal structural logger — events use the `domain.noun.verb` taxonomy. */
export interface ManifestPollLogger {
  info(event: string, ctx?: Record<string, unknown>): void;
  warn(event: string, ctx?: Record<string, unknown>): void;
  error(event: string, ctx?: Record<string, unknown>): void;
}

export interface ManifestAdoptDeps {
  manifestProvider: IManifestProvider;
  manifestVersionStore: IManifestVersionStore;
  /** Locally-pinned officer root keys (CELLO_CONSORTIUM_ROOT_KEYS). */
  rootKeys: readonly string[];
  threshold: number;
  logger: ManifestPollLogger;
}

export type ManifestPollFailureReason =
  | "manifest_http_unreachable"
  | "manifest_malformed"
  | "manifest_threshold_invalid"
  | "manifest_signature_invalid"
  | "manifest_not_yet_valid"
  | "manifest_expired"
  | "manifest_version_rollback";

export type ManifestPollOutcome =
  | { ok: true; adopted: boolean; oldVersion: number | null; newVersion: number }
  | { ok: false; reason: ManifestPollFailureReason };

const FETCH_TIMEOUT_MS = 10_000;

/**
 * Fetch the consortium manifest over HTTP, verify it (TUF), and adopt it if it is a
 * newer, validly-signed, unexpired manifest. Never throws — a poll failure returns a
 * distinct reason and leaves the cached manifest + trusted version untouched (DB-001).
 */
export async function pollManifestOverHttp(
  opts: {
    directoryUrl: string;
    fetchFn?: typeof fetch;
    now?: Date;
    correlationId?: string;
  } & ManifestAdoptDeps,
): Promise<ManifestPollOutcome> {
  const {
    directoryUrl,
    fetchFn = fetch,
    now = new Date(),
    correlationId,
    manifestProvider,
    manifestVersionStore,
    rootKeys,
    threshold,
    logger,
  } = opts;
  const manifestUrl = `${directoryUrl.replace(/\/$/, "")}/manifest`;

  // 1. Fetch. Any network error / non-200 / timeout → unreachable. DB-001: the caller
  //    keeps the cached manifest; a poll failure never disturbs agent connections.
  let raw: unknown;
  try {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);
    let resp: Response;
    try {
      resp = await fetchFn(manifestUrl, { signal: ac.signal });
    } finally {
      clearTimeout(timer);
    }
    if (!resp.ok) {
      logger.warn("manifest.http.poll.failed", { reason: "manifest_http_unreachable", status: resp.status, directoryUrl, correlationId });
      return { ok: false, reason: "manifest_http_unreachable" };
    }
    raw = await resp.json();
  } catch (err: unknown) {
    logger.warn("manifest.http.poll.failed", { reason: "manifest_http_unreachable", directoryUrl, correlationId, error: err instanceof Error ? err.message : String(err) });
    return { ok: false, reason: "manifest_http_unreachable" };
  }

  // 2. Structural check before verify — a junk body must fail loudly, not be cached.
  const manifest = raw as ConsortiumManifest;
  if (
    typeof (manifest as { version?: unknown })?.version !== "number" ||
    !Array.isArray((manifest as { nodes?: unknown })?.nodes) ||
    !Array.isArray((manifest as { signatures?: unknown })?.signatures)
  ) {
    logger.warn("manifest.http.poll.failed", { reason: "manifest_malformed", directoryUrl, correlationId });
    return { ok: false, reason: "manifest_malformed" };
  }

  // 3. Defense-in-depth: never adopt against a 0/missing threshold (verifyManifest would
  //    accept an unsigned manifest at threshold 0). The composition root rejects
  //    threshold < 1 before wiring, but guard the policy directly too.
  if (threshold < 1) {
    logger.error("manifest.http.poll.failed", { reason: "manifest_threshold_invalid", threshold, correlationId });
    return { ok: false, reason: "manifest_threshold_invalid" };
  }

  // 4. Threshold signature (RFC 8032) against locally-pinned root keys.
  const verifyResult = verifyManifest(manifest as unknown as ConsortiumManifestInput, rootKeys, threshold);
  if (!verifyResult.ok) {
    logger.warn("manifest.http.poll.failed", { reason: "manifest_signature_invalid", manifestVersion: manifest.version, detail: verifyResult.reason, correlationId });
    return { ok: false, reason: "manifest_signature_invalid" };
  }

  // 5. Validity window.
  if (now < new Date(manifest.not_before)) {
    logger.warn("manifest.http.poll.failed", { reason: "manifest_not_yet_valid", manifestVersion: manifest.version, notBefore: manifest.not_before, correlationId });
    return { ok: false, reason: "manifest_not_yet_valid" };
  }
  if (new Date(manifest.expires) <= now) {
    logger.error("manifest.http.poll.failed", { reason: "manifest_expired", manifestVersion: manifest.version, expiresAt: manifest.expires, correlationId });
    return { ok: false, reason: "manifest_expired" };
  }

  // 6. Anti-rollback — never adopt a version older than the trusted floor.
  const lastSeen = await manifestVersionStore.getLastSeenVersion();
  if (lastSeen !== null && manifest.version < lastSeen) {
    logger.warn("manifest.http.poll.failed", { reason: "manifest_version_rollback", manifestVersion: manifest.version, lastSeenVersion: lastSeen, correlationId });
    return { ok: false, reason: "manifest_version_rollback" };
  }
  if (lastSeen !== null && manifest.version === lastSeen) {
    // Already current — nothing to adopt.
    return { ok: true, adopted: false, oldVersion: lastSeen, newVersion: manifest.version };
  }

  // 7. Adopt.
  const oldVersion = manifestProvider.getCurrentManifest()?.version ?? null;
  manifestProvider.updateManifest(manifest);
  await manifestVersionStore.persistVersion(manifest.version);
  logger.info("manifest.http.poll.success", { oldVersion, newVersion: manifest.version, directoryUrl, correlationId });
  return { ok: true, adopted: true, oldVersion, newVersion: manifest.version };
}

/**
 * Wire the daemon-level HTTP manifest poll onto a scheduler. Self-rearming: each tick
 * polls then schedules the next. Returns a stop function. The poll runs regardless of
 * how many agents exist (including zero) — it has no agent identity and opens no
 * signaling connection.
 */
export function startHttpManifestPoll(
  opts: {
    scheduler: IManifestPollScheduler;
    directoryUrl: string;
    fetchFn?: typeof fetch;
    mintCorrelationId?: () => string;
  } & ManifestAdoptDeps,
): () => void {
  const { scheduler, directoryUrl, fetchFn, mintCorrelationId, manifestProvider, manifestVersionStore, rootKeys, threshold, logger } = opts;
  let stopped = false;

  const tick = async (): Promise<void> => {
    if (stopped) return;
    await pollManifestOverHttp({
      directoryUrl,
      fetchFn,
      correlationId: mintCorrelationId?.(),
      manifestProvider,
      manifestVersionStore,
      rootKeys,
      threshold,
      logger,
    }).catch(() => {
      // pollManifestOverHttp never throws for poll failures; guard so the loop self-heals.
    });
    if (!stopped) scheduler.scheduleNext(tick);
  };

  scheduler.scheduleNext(tick);
  return () => {
    stopped = true;
    scheduler.cancel();
  };
}
