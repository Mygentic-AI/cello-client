#!/usr/bin/env node
/**
 * cello — the CELLO CLI binary.
 *
 * There is no dispatch switch here. Every command lives in the registry (src/registry.ts), which is
 * also what renders `cello --help` and per-command help — so dispatch, the command table, and the
 * help text cannot drift apart. Adding a command means adding one registry entry; this binary does
 * not change.
 *
 * The bash-adapter contract (§3): a command's JSON result goes to stdout, a structured failure goes
 * to stderr VERBATIM, and the exit code branches on it — so any bash-capable agent can drive a
 * CELLO node with `cello <cmd> | jq` and `$?`, with no MCP dependency.
 */

import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { createRequire } from "node:module";
import { KNOWN_COMMANDS, USAGE, checkArgs, helpForCommand, topLevelFlag } from "../cli-args.js";
import { findCommand, type CommandContext } from "../registry.js";
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
  // `cello --version` / `--help` are FLAGS, not commands — answer them before the command lookup,
  // which would otherwise treat them as an unknown command (help text, exit 1).
  const topFlag = topLevelFlag(command);
  if (topFlag === "version") {
    const pkg = require("../../package.json") as { version: string };
    process.stdout.write(`${pkg.version}\n`);
    process.exit(0);
    return;
  }
  if (topFlag === "help") {
    process.stdout.write(USAGE + "\n");
    process.exit(0);
    return;
  }

  const spec = command ? findCommand(command) : undefined;

  if (!spec || !KNOWN_COMMANDS.has(command)) {
    // No command, or one we don't have: print the described command table.
    process.stdout.write(USAGE + "\n");
    process.exit(command ? 1 : 0);
    return;
  }

  const args = process.argv.slice(3);

  // Answer --help/-h on every subcommand and REJECT unknown flags BEFORE dispatch, so a flag can
  // never be coerced into a positional argument.
  const check = checkArgs(command, args);
  if (check.kind === "help") {
    process.stdout.write(helpForCommand(command, args) + "\n");
    process.exit(0);
    return;
  }
  if (check.kind === "unknown_flag") {
    process.stderr.write(`Unknown flag '${check.flag}' for 'cello ${command}'.\n`);
    process.stdout.write(helpForCommand(command, args) + "\n");
    process.exit(1);
    return;
  }

  const ctx: CommandContext = {
    celloDir,
    daemonBin,
    logger,
    onProgress: (line) => process.stdout.write(line + "\n"),
  };

  const result = await spec.run(ctx, args);

  // Report the outcome, never the intent: stdout carries the result, stderr the structured failure.
  if (result.stdout.length > 0) process.stdout.write(result.stdout + "\n");
  if (result.stderr.length > 0) process.stderr.write(result.stderr + "\n");
  process.exit(result.exitCode);
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`Fatal: ${message}\n`);
  process.exit(1);
});
