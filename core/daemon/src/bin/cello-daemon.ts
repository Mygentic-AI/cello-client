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
import type { Logger } from "../types.js";

const MAX_CONNECTIONS = 16;

// Composition root: stdout JSON logger
const logger: Logger = {
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
  const handle = await startDaemon({
    celloDir,
    socketPath,
    lockFilePath,
    maxConnections: MAX_CONNECTIONS,
    version,
    logger,
  });

  // SIGTERM/SIGINT → graceful shutdown
  const shutdown = async (signal: string): Promise<void> => {
    await handle.stop(signal);
    process.exit(0);
  };

  process.on("SIGTERM", () => { shutdown("SIGTERM"); });
  process.on("SIGINT", () => { shutdown("SIGINT"); });
}

main().catch((err: unknown) => {
  logger.error("daemon.startup.failed", {
    error: err instanceof Error ? err.message : String(err),
  });
  process.exit(1);
});
