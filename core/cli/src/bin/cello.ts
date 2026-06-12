#!/usr/bin/env node
/**
 * cello — the CELLO CLI binary.
 *
 * Commands:
 *   cello login   — Start the daemon (or connect to existing), exit 0
 *   cello logout  — Send shutdown command to daemon
 *   cello status  — Query daemon and print structured JSON response
 */

import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { createRequire } from "node:module";
import { login, logout, status } from "../commands.js";
import type { Logger } from "@cello-protocol/daemon";

const logger: Logger = {
  info(event: string, context: Record<string, unknown>): void {
    const line = JSON.stringify({ level: "info", event, ...context, ts: new Date().toISOString() });
    process.stderr.write(line + "\n");
  },
  warn(event: string, context: Record<string, unknown>): void {
    const line = JSON.stringify({ level: "warn", event, ...context, ts: new Date().toISOString() });
    process.stderr.write(line + "\n");
  },
  error(event: string, context: Record<string, unknown>): void {
    const line = JSON.stringify({ level: "error", event, ...context, ts: new Date().toISOString() });
    process.stderr.write(line + "\n");
  },
};

const celloDir = process.env.CELLO_DIR || join(homedir(), ".cello");
const command = process.argv[2];

// Resolve daemon binary via package resolution (works after npm publish)
const require = createRequire(import.meta.url);
const daemonPkgPath = require.resolve("@cello-protocol/daemon/package.json");
const daemonBin = join(dirname(daemonPkgPath), "dist/bin/cello-daemon.js");

async function main(): Promise<void> {
  let result: { exitCode: number; output: string };

  switch (command) {
    case "login":
      result = await login(celloDir, daemonBin, logger);
      break;
    case "logout":
      result = await logout(celloDir);
      break;
    case "status":
      result = await status(celloDir);
      break;
    default:
      process.stdout.write("Usage: cello <login|logout|status>\n");
      process.exit(command ? 1 : 0);
      return;
  }

  process.stdout.write(result.output + "\n");
  process.exit(result.exitCode);
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`Fatal: ${message}\n`);
  process.exit(1);
});
