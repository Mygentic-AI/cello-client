#!/usr/bin/env node
/**
 * cello — the CELLO CLI binary.
 *
 * Commands:
 *   cello login    — Start the daemon (or connect to existing), exit 0
 *   cello logout   — Send shutdown command to daemon
 *   cello status   — Query daemon and print structured JSON response
 *   cello register — Register a loaded agent with the directory (ML-DSA + FROST DKG)
 */

import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { createRequire } from "node:module";
import { login, logout, status, register, createAgent, removeAgent, sessions, type SessionFilter } from "../commands.js";
import type { Logger } from "@cello-protocol/daemon";

const logger: Logger = {
  debug(event: string, context: Record<string, unknown>): void {
    const line = JSON.stringify({ level: "debug", event, ...context, ts: new Date().toISOString() });
    process.stderr.write(line + "\n");
  },
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
    case "register": {
      // cello register <agent> [preAuthToken]  (token falls back to CELLO_PREAUTH_TOKEN
      // so it need not appear in shell history). Optional phone stub follows.
      const agent = process.argv[3] ?? "";
      const tokenArg = process.argv[4];
      const preAuthToken = tokenArg ?? process.env.CELLO_PREAUTH_TOKEN ?? "";
      const phoneStub = process.argv[5] ?? "";
      // L3: a token passed as an argv positional is visible in the process list
      // (ps / /proc). Warn and steer to the env var, which is the safe path.
      if (tokenArg) {
        process.stderr.write(
          "Warning: passing the pre-auth token as a command-line argument exposes it in the process list. Prefer the CELLO_PREAUTH_TOKEN environment variable.\n",
        );
      }
      result = await register(celloDir, agent, preAuthToken, phoneStub);
      break;
    }
    case "create-agent": {
      // cello create-agent <name> — create a fresh local agent identity (PERSIST-002 AC-004).
      const name = process.argv[3] ?? "";
      result = await createAgent(celloDir, name);
      break;
    }
    case "remove-agent": {
      // cello remove-agent <name> — retire a local agent (one-way) and free its name (REMOVE-001).
      const name = process.argv[3] ?? "";
      result = await removeAgent(celloDir, name);
      break;
    }
    case "sessions": {
      // cello sessions [--open|--closed|--failed|--all] [--limit N] — the full session history.
      // Defaults to open (live + resumable) so failed/closed don't flood it; the daemon caps the
      // count. (`cello status` only ever shows live/resumable, never this full list.)
      const args = process.argv.slice(3);
      let filter: SessionFilter | undefined;
      if (args.includes("--all")) filter = "all";
      else if (args.includes("--closed")) filter = "closed";
      else if (args.includes("--failed")) filter = "failed";
      else if (args.includes("--open")) filter = "open";
      const limitIdx = args.indexOf("--limit");
      let limit: number | undefined;
      if (limitIdx !== -1 && args[limitIdx + 1] !== undefined) {
        const n = Number(args[limitIdx + 1]);
        if (Number.isFinite(n) && n > 0) limit = Math.floor(n);
      }
      result = await sessions(celloDir, { filter, limit });
      break;
    }
    default:
      process.stdout.write("Usage: cello <login|logout|status|register|create-agent|remove-agent|sessions>\n");
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
