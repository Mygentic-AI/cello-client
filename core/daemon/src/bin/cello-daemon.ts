#!/usr/bin/env node
/**
 * cello-daemon — the long-running CELLO daemon process.
 *
 * This binary is spawned by `cello login` as a detached background process.
 * It manages agent identities, IPC connections, and (future) directory signaling.
 *
 * Environment variables:
 *   CELLO_DIR       Override ~/.cello directory (default: ~/.cello)
 *   CELLO_VERSION   Version string for lock file (default: from package.json)
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { startDaemon } from "../daemon.js";
import { createDirectoryEndpointResolver } from "../directory-bootstrap.js";
import { FileManifestProvider } from "../file-manifest-provider.js";
import { RandomizedPollScheduler } from "../manifest-poll-scheduler.js";
import type { Logger } from "../types.js";
import { ManifestDirectoryChallengeVerifier, type IManifestProvider, type IDirectoryChallengeVerifier, type IManifestVersionStore, type IManifestPollScheduler } from "@cello-protocol/transport";

const MAX_CONNECTIONS = 16;

// Composition root: stdout JSON logger
const logger: Logger = {
  debug(event: string, context: Record<string, unknown>): void {
    const line = JSON.stringify({ level: "debug", event, ...context, ts: new Date().toISOString() });
    process.stdout.write(line + "\n");
  },
  info(event: string, context: Record<string, unknown>): void {
    const line = JSON.stringify({ level: "info", event, ...context, ts: new Date().toISOString() });
    process.stdout.write(line + "\n");
  },
  warn(event: string, context: Record<string, unknown>): void {
    const line = JSON.stringify({ level: "warn", event, ...context, ts: new Date().toISOString() });
    process.stdout.write(line + "\n");
  },
  error(event: string, context: Record<string, unknown>): void {
    const line = JSON.stringify({ level: "error", event, ...context, ts: new Date().toISOString() });
    process.stdout.write(line + "\n");
  },
};

const celloDir = process.env.CELLO_DIR || join(homedir(), ".cello");
const socketPath = join(celloDir, "daemon.sock");
const lockFilePath = join(celloDir, "daemon.lock");
const version = process.env.CELLO_VERSION || "0.0.1";

/**
 * Build the optional consortium-manifest deps from the environment (M7 J-AUTH).
 *
 *   CELLO_CONSORTIUM_MANIFEST    absolute path to the manifest JSON
 *   CELLO_CONSORTIUM_ROOT_KEYS   comma-separated officer root pubkeys (hex)
 *   CELLO_CONSORTIUM_THRESHOLD   minimum officer signatures (integer)
 *
 * When the manifest path is unset, returns {} — step-6 stays off (M6 compat).
 * One FileManifestProvider instance is shared between startDaemon's loadAndVerify
 * call and the ManifestDirectoryChallengeVerifier, so step-6 reads the same cached,
 * verified manifest.
 */
function buildManifestDeps(logger: Logger): {
  manifestProvider?: IManifestProvider;
  manifestRootKeys?: readonly string[];
  manifestThreshold?: number;
  challengeVerifier?: IDirectoryChallengeVerifier;
  manifestVersionStore?: IManifestVersionStore;
  manifestPollScheduler?: IManifestPollScheduler;
} {
  const manifestPath = process.env.CELLO_CONSORTIUM_MANIFEST;
  if (!manifestPath) return {};

  const rootKeysRaw = process.env.CELLO_CONSORTIUM_ROOT_KEYS ?? "";
  const manifestRootKeys = rootKeysRaw.split(",").map((k) => k.trim()).filter((k) => k.length > 0);
  const manifestThreshold = Number.parseInt(process.env.CELLO_CONSORTIUM_THRESHOLD ?? "", 10);
  if (manifestRootKeys.length === 0 || Number.isNaN(manifestThreshold)) {
    throw new Error(
      "CELLO_CONSORTIUM_MANIFEST is set but CELLO_CONSORTIUM_ROOT_KEYS / CELLO_CONSORTIUM_THRESHOLD are missing or invalid",
    );
  }

  const manifestProvider = new FileManifestProvider({ path: manifestPath });
  const challengeVerifier = new ManifestDirectoryChallengeVerifier(manifestProvider);
  // Anti-rollback (DOD-AUTH-2 / TUF): the last-verified manifest version is persisted to refuse a
  // manifest whose version regressed across restarts. PERSIST-002 (AC-008): this now lives in the
  // encrypted manifest_state table (a manifest-version.json file is no longer written) — startDaemon
  // constructs the DB-backed store itself after opening the DB, so the bin injects nothing here.
  // DOD-AUTH-2: background manifest poll. The directory is re-polled on a randomized
  // 6–12h interval (thundering-herd avoidance) and a newer signed manifest is adopted.
  // The interval is env-injectable so the live binary test can poll sub-second instead
  // of waiting hours; production leaves these unset → the 6–12h default window.
  // Both-or-neither, positive, min <= max — a partial/invalid override fails LOUDLY
  // rather than silently reverting to 6–12h or producing a negative (tight-loop) delay.
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

async function main(): Promise<void> {
  // M7 Keystone (Part 1): give the daemon its door to the directory. The resolver
  // discovers the directory endpoint via GET ${CELLO_DIRECTORY_URL}/bootstrap (the
  // proven M6 path); startDaemon builds the real signalingConnect from it + the
  // primary agent identity.
  // FINDING-4: this resolver is wrapped by the daemon's roster-aware failover resolver, which owns
  // ALL fallback semantics (roster + sticky). staleFallback:false makes it report a dead primary as
  // null on a fresh /bootstrap failure — WITHOUT it, the wrapper would keep receiving the stale dead
  // endpoint and never fail over (the exact live kill-primary bug). The roster is the real fallback.
  const directoryEndpointResolver = createDirectoryEndpointResolver({ logger, staleFallback: false });

  // M7 J-AUTH (DOD-AUTH-1/2): the consortium-manifest hardening is OPT-IN. When the
  // operator (or the live harness) configures a manifest, the daemon loads + verifies
  // it (threshold officer signatures + validity window) and verifies the directory's
  // step-6 identity proof against the node pubkeys in that manifest. When unset, the
  // daemon runs the M6 backward-compat path: no challengeVerifier → step-6 skipped.
  // Both dialers (keystone + per-agent) receive the verifier via startDaemon.
  const manifest = buildManifestDeps(logger);

  const handle = await startDaemon({
    celloDir,
    socketPath,
    lockFilePath,
    maxConnections: MAX_CONNECTIONS,
    version,
    logger,
    directoryEndpointResolver,
    ...manifest,
  });

  const shutdown = async (signal: string): Promise<void> => {
    await handle.stop(signal);
    process.exit(0);
  };

  process.on("SIGTERM", () => {
    try {
      shutdown("SIGTERM").catch((err: unknown) => {
        logger.error("daemon.shutdown.failed", {
          signal: "SIGTERM",
          error: err instanceof Error ? err.message : String(err),
        });
        process.exit(1);
      });
    } catch (err: unknown) {
      logger.error("daemon.shutdown.failed", {
        signal: "SIGTERM",
        error: err instanceof Error ? err.message : String(err),
      });
      process.exit(1);
    }
  });
  process.on("SIGINT", () => {
    try {
      shutdown("SIGINT").catch((err: unknown) => {
        logger.error("daemon.shutdown.failed", {
          signal: "SIGINT",
          error: err instanceof Error ? err.message : String(err),
        });
        process.exit(1);
      });
    } catch (err: unknown) {
      logger.error("daemon.shutdown.failed", {
        signal: "SIGINT",
        error: err instanceof Error ? err.message : String(err),
      });
      process.exit(1);
    }
  });
}

main().catch((err: unknown) => {
  logger.error("daemon.startup.failed", {
    error: err instanceof Error ? err.message : String(err),
  });
  process.exit(1);
});
