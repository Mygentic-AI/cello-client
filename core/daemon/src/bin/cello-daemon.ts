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
import { FileManifestVersionStore } from "../manifest-version-store-file.js";
import type { Logger } from "../types.js";
import { ManifestDirectoryChallengeVerifier, type IManifestProvider, type IDirectoryChallengeVerifier, type IManifestVersionStore } from "@cello-protocol/transport";

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
  // Anti-rollback (DOD-AUTH-2 / TUF): persist the last-verified manifest version under
  // ~/.cello so the daemon refuses a manifest whose version regressed across restarts.
  // The daemon (startDaemon) reads getLastSeenVersion() before accepting a manifest and
  // persistVersion() on success; a version < trusted → directory.auth.manifest.version.rollback.
  const manifestVersionStore = new FileManifestVersionStore(join(celloDir, "manifest-version.json"));
  logger.info("daemon.manifest.configured", {
    manifestPath,
    rootKeyCount: manifestRootKeys.length,
    threshold: manifestThreshold,
  });
  return { manifestProvider, manifestRootKeys, manifestThreshold, challengeVerifier, manifestVersionStore };
}

async function main(): Promise<void> {
  // M7 Keystone (Part 1): give the daemon its door to the directory. The resolver
  // discovers the directory endpoint via GET ${CELLO_DIRECTORY_URL}/bootstrap (the
  // proven M6 path); startDaemon builds the real signalingConnect from it + the
  // primary agent identity.
  const directoryEndpointResolver = createDirectoryEndpointResolver({ logger });

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
