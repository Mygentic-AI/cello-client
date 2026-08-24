/**
 * Composition helper for the daemon's consortium-manifest dependencies (M7 J-AUTH / FINDING-4).
 *
 * Extracted from bin/cello-daemon.ts so it can be unit-tested without triggering the bin's
 * top-level main() (which spawns a live daemon on import).
 *
 * Two modes:
 *   - DEFAULT (no CELLO_CONSORTIUM_MANIFEST): load the COMPILED-IN consortium roster
 *     (bundled-consortium-manifest.ts) with step-6 directory identity auth ON — the full production
 *     posture that makes cold-boot directory failover possible (FINDING-4 redundancy invariant).
 *   - OVERRIDE (CELLO_CONSORTIUM_MANIFEST set): operator-supplied manifest FILE + env root keys /
 *     threshold, plus the optional background /manifest poll. The pre-FINDING-4 opt-in path.
 */

import {
  ManifestDirectoryChallengeVerifier,
  type IManifestProvider,
  type IDirectoryChallengeVerifier,
  type IManifestVersionStore,
  type IManifestPollScheduler,
} from "@cello-protocol/transport";
import { FileManifestProvider, EmbeddedManifestProvider } from "./file-manifest-provider.js";
import {
  BUNDLED_CONSORTIUM_MANIFEST,
  BUNDLED_CONSORTIUM_ROOT_KEYS,
  BUNDLED_CONSORTIUM_THRESHOLD,
} from "./bundled-consortium-manifest.js";
import { resolveDirectoryUrl } from "./directory-bootstrap.js";
import { RandomizedPollScheduler } from "./manifest-poll-scheduler.js";
import type { Logger } from "./types.js";
import { remedyFor, type ManifestOrigin } from "./manifest-validity.js";

/** Normalize a directory URL for comparison (trim, drop trailing slashes, lowercase). */
function normalizeUrl(u: string): string {
  return u.trim().replace(/\/+$/, "").toLowerCase();
}

/** The set of directory endpoints the bundled roster describes (normalized). */
const BUNDLED_ENDPOINTS = new Set(
  BUNDLED_CONSORTIUM_MANIFEST.nodes.map((n) => normalizeUrl(String((n as Record<string, unknown>)["endpoint"]))),
);

export interface ManifestDeps {
  manifestProvider?: IManifestProvider;
  manifestRootKeys?: readonly string[];
  manifestThreshold?: number;
  challengeVerifier?: IDirectoryChallengeVerifier;
  manifestVersionStore?: IManifestVersionStore;
  manifestPollScheduler?: IManifestPollScheduler;
}

/**
 * Build the consortium-manifest deps.
 *
 *   CELLO_CONSORTIUM_MANIFEST    absolute path to an override manifest JSON (opt-in)
 *   CELLO_CONSORTIUM_ROOT_KEYS   comma-separated officer root pubkeys (hex) — override path only
 *   CELLO_CONSORTIUM_THRESHOLD   minimum officer signatures (integer) — override path only
 *   CELLO_MANIFEST_POLL_MIN_MS / _MAX_MS   optional background poll window — override path only
 *
 * The single manifestProvider instance is shared between startDaemon's loadAndVerify call and the
 * ManifestDirectoryChallengeVerifier, so step-6 reads the same cached, verified manifest.
 */
/**
 * DOD-M15-EXPIRY-CONSUMER-POLICY-1 — ONE callback, built per origin.
 *
 * It was duplicated verbatim across the bundled and file branches, and the one place the two copies
 * had to DIFFER was the one place they were identical: the remedy. "Install a current manifest and
 * restart" is advice that cannot be followed on the bundled path — the manifest is compiled in, that
 * branch wires no poll, so it can never self-heal — and the workaround an operator reaches for
 * instead (repointing CELLO_DIRECTORY_URL) starts the daemon with directory identity authentication
 * SILENTLY OFF. Guidance that routes a stuck operator into disabling a security control is a defect
 * in the guidance, which `remedyFor` already exists to prevent.
 */
function lapsedManifestReporter(
  logger: Logger,
  origin: ManifestOrigin,
): (info: { nodeId: string; version: number; expires: string }) => void {
  return (info) => {
    logger.warn("directory.auth.manifest.lapsed", {
      ...info,
      origin,
      impact:
        "a directory node was SUCCESSFULLY authenticated against a manifest whose validity window " +
        "has closed, so its key was trusted on the strength of a check that has expired. If that " +
        "node has been rotated or removed since, this daemon would not know.",
      guidance:
        "Signaling was NOT blocked — refusing here would leave a long-running daemon unable to " +
        "authenticate any directory, taking every agent offline. " + remedyFor(origin) +
        " cello_status reports the expiry.",
    });
  };
}

export function buildManifestDeps(logger: Logger): ManifestDeps {
  const manifestPath = process.env.CELLO_CONSORTIUM_MANIFEST;
  if (!manifestPath) {
    // FINDING-4 default: load the COMPILED-IN consortium roster so the daemon already knows every
    // sovereign directory — and can fail over to a reachable one — even when its primary is down
    // (the redundancy invariant), AND enforces step-6 directory identity auth against the bundled
    // node pubkeys (defeats a /bootstrap MITM redirecting failover to a rogue directory). This is
    // the full production posture with zero operator config. The manifest is re-verified against the
    // pinned root keys at load by startDaemon (ADV-002 — a corrupt embedded manifest fails CLOSED,
    // never a silent downgrade). No poll scheduler: the bundled roster is static; adopting runtime
    // manifest updates via the /manifest poll is a separate opt-in reachable through the env path.
    //
    // GATE (do NOT enable step-6 against a directory the bundle can't authenticate): the bundled
    // manifest is the trust anchor for the PRODUCTION consortium ONLY (the mygentic.ai directories
    // it lists). When the operator has pointed CELLO_DIRECTORY_URL at a directory that is NOT in the
    // bundle — local dev (`CELLO_ENV=local`) and the e2e spine harness both run their own local
    // directory on 127.0.0.1 — the bundled node pubkeys don't describe it, so enforcing step-6 would
    // wrongly reject every connection (key_not_in_manifest). In that case fall through to the M6
    // backward-compat path (no roster, no step-6); those deployments opt into step-6 explicitly by
    // supplying a matching manifest via CELLO_CONSORTIUM_MANIFEST. Unset URL → the production default,
    // which is a bundled node's ADDRESS and so matches, giving real operators the full posture.
    //
    // The comparison is byte-equality against the roster, not "reaches the same machine". A DNS name
    // for a bundled node does NOT match and lands here, in the branch that turns step-6 off — which
    // is why PRODUCTION_DIRECTORY_URL is an address. Do not "tidy" either into a hostname.
    const directoryUrl = normalizeUrl(resolveDirectoryUrl());
    if (!BUNDLED_ENDPOINTS.has(directoryUrl)) {
      // Two very different situations reach here and they must not log the same way. A loopback or
      // private address is local dev or the e2e harness pointing at its own directory — designed and
      // benign. Anything else is a client running against a PUBLIC directory with identity
      // authentication off, which is a weaker client than the operator believes they have, and the
      // only previous signal was the absence of a different log line.
      const isLocal = /^https?:\/\/(localhost|127\.|\[::1\]|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(
        directoryUrl,
      );
      const detail = { directoryUrl, reason: "directory_not_in_bundled_roster", step6: "disabled" };
      if (isLocal) logger.info("daemon.manifest.bundled.skipped", detail);
      else logger.warn("daemon.manifest.bundled.skipped", detail);
      return {};
    }
    const manifestProvider = new EmbeddedManifestProvider(BUNDLED_CONSORTIUM_MANIFEST);
    const challengeVerifier = new ManifestDirectoryChallengeVerifier(
      manifestProvider, lapsedManifestReporter(logger, "bundled"));
    logger.info("daemon.manifest.bundled", {
      version: BUNDLED_CONSORTIUM_MANIFEST.version,
      nodeCount: BUNDLED_CONSORTIUM_MANIFEST.nodes.length,
      rootKeyCount: BUNDLED_CONSORTIUM_ROOT_KEYS.length,
      threshold: BUNDLED_CONSORTIUM_THRESHOLD,
    });
    return {
      manifestProvider,
      manifestRootKeys: BUNDLED_CONSORTIUM_ROOT_KEYS,
      manifestThreshold: BUNDLED_CONSORTIUM_THRESHOLD,
      challengeVerifier,
    };
  }

  const rootKeysRaw = process.env.CELLO_CONSORTIUM_ROOT_KEYS ?? "";
  const manifestRootKeys = rootKeysRaw.split(",").map((k) => k.trim()).filter((k) => k.length > 0);
  const manifestThreshold = Number.parseInt(process.env.CELLO_CONSORTIUM_THRESHOLD ?? "", 10);
  if (manifestRootKeys.length === 0 || Number.isNaN(manifestThreshold)) {
    throw new Error(
      "CELLO_CONSORTIUM_MANIFEST is set but CELLO_CONSORTIUM_ROOT_KEYS / CELLO_CONSORTIUM_THRESHOLD are missing or invalid",
    );
  }

  const manifestProvider = new FileManifestProvider({ path: manifestPath });
  const challengeVerifier = new ManifestDirectoryChallengeVerifier(
    manifestProvider, lapsedManifestReporter(logger, "file"));
  // DOD-AUTH-2: background manifest poll. The directory is re-polled on a randomized 6–12h interval
  // (thundering-herd avoidance) and a newer signed manifest is adopted. The interval is env-injectable
  // so the live binary test can poll sub-second instead of waiting hours; production leaves these
  // unset → the 6–12h default window. Both-or-neither, positive, min <= max — a partial/invalid
  // override fails LOUDLY rather than silently reverting or producing a negative (tight-loop) delay.
  const rawPollMin = process.env.CELLO_MANIFEST_POLL_MIN_MS;
  const rawPollMax = process.env.CELLO_MANIFEST_POLL_MAX_MS;
  let pollOpts: { minMs: number; maxMs: number } | undefined;
  if (rawPollMin !== undefined || rawPollMax !== undefined) {
    const minMs = Number.parseInt(rawPollMin ?? "", 10);
    const maxMs = Number.parseInt(rawPollMax ?? "", 10);
    if (Number.isNaN(minMs) || Number.isNaN(maxMs) || minMs <= 0 || maxMs < minMs) {
      throw new Error(
        "CELLO_MANIFEST_POLL_MIN_MS / _MAX_MS must BOTH be set to positive integers with min <= max",
      );
    }
    pollOpts = { minMs, maxMs };
  }
  const manifestPollScheduler = new RandomizedPollScheduler(pollOpts);
  logger.info("daemon.manifest.configured", {
    manifestPath,
    rootKeyCount: manifestRootKeys.length,
    threshold: manifestThreshold,
    pollMinMs: pollOpts?.minMs ?? null,
    pollMaxMs: pollOpts?.maxMs ?? null,
  });
  return { manifestProvider, manifestRootKeys, manifestThreshold, challengeVerifier, manifestPollScheduler };
}
