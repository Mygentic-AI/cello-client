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
import { buildManifestDeps } from "../manifest-deps.js";
// EXIT_ALREADY_RUNNING is distinct from 1 (generic startup failure) so a caller can tell "lost the
// race" from "broken" — connectOrStart relies on exactly that distinction, so the constant is shared
// rather than written down twice.
import { DaemonAlreadyRunningError, EXIT_ALREADY_RUNNING } from "../singleton-lock.js";
import type { Logger } from "../types.js";

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

  // M7 J-AUTH (DOD-AUTH-1/2) + FINDING-4: consortium-manifest deps. buildManifestDeps chooses:
  //   - DEFAULT (no CELLO_CONSORTIUM_MANIFEST) — load the COMPILED-IN production roster + step-6
  //     directory identity auth, so a cold-boot daemon knows every directory and can fail over to a
  //     reachable one (redundancy invariant). Gated on CELLO_DIRECTORY_URL actually being a bundled
  //     node — a daemon pointed at a local/non-bundled directory (local dev, e2e spine harness) gets
  //     the M6 backward-compat path (no roster, no step-6) instead of wrongly failing step-6.
  //   - OVERRIDE (CELLO_CONSORTIUM_MANIFEST set) — operator-supplied manifest FILE + env root keys /
  //     threshold + optional /manifest poll (the pre-FINDING-4 opt-in path).
  // When a manifest is active, the daemon verifies the directory's step-6 identity proof against the
  // node pubkeys in it. Both dialers (keystone + per-agent) receive the verifier via startDaemon.
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
  // DOD-SINGLE-DAEMON-1 (AC2): losing the singleton race is not a crash — it is the system working.
  // Say so in one plain line an operator can act on, name the pid that holds the lock, and exit
  // non-zero without a stack trace. Two daemons is the silent, wrong outcome; this is the loud, right
  // one.
  if (err instanceof DaemonAlreadyRunningError) {
    logger.info("daemon.start.refused", { reason: "already_running", holderPid: err.holderPid });
    process.stderr.write(`${err.message}\n`);
    process.exit(EXIT_ALREADY_RUNNING);
  }
  logger.error("daemon.startup.failed", {
    error: err instanceof Error ? err.message : String(err),
  });
  process.exit(1);
});
