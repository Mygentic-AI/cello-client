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
import { login, logout, status, register, createAgent, removeAgent, refreshShares, relayReceipts, sessions, type SessionFilter, contactAdd, contactRemove, contactList } from "../commands.js";
import { USAGE, KNOWN_COMMANDS, checkArgs, helpForCommand } from "../cli-args.js";
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

  // M8B F2: answer --help/-h on every subcommand and REJECT unknown flags before
  // dispatch, so a flag can never be coerced into a positional argument (previously
  // `cello register --help` tried to register an agent literally named "--help").
  if (command && KNOWN_COMMANDS.has(command as never)) {
    const check = checkArgs(command, process.argv.slice(3));
    if (check.kind === "help") {
      process.stdout.write(helpForCommand(command) + "\n");
      process.exit(0);
      return;
    }
    if (check.kind === "unknown_flag") {
      process.stderr.write(`Unknown flag '${check.flag}' for 'cello ${command}'.\n`);
      process.stdout.write(helpForCommand(command) + "\n");
      process.exit(1);
      return;
    }
  }

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
      const preAuthToken = process.argv[4] ?? process.env.CELLO_PREAUTH_TOKEN ?? "";
      const phoneStub = process.argv[5] ?? "";
      // M8C-ONBOARD-WARN-1 (revised 2026-07-06, Andre): the pre-auth exposure "note" is REMOVED
      // entirely. A single-use, 24h, consumed-on-success token has no meaningful exposure risk, so
      // the note only drew attention to a non-issue ("this thing you weren't worried about? don't
      // worry about it") — pure noise on the core onboarding path. No warning at all is correct.
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
    case "refresh": {
      // cello refresh <name> — proactive share refresh / epoch rollover (M8B DOD-REFRESH-1).
      const name = process.argv[3] ?? "";
      result = await refreshShares(celloDir, name);
      break;
    }
    case "receipts": {
      // cello receipts <name> — list the agent's stored relay ordering receipts (M8B DOD-RELAYSIG-1).
      const name = process.argv[3] ?? "";
      result = await relayReceipts(celloDir, name);
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
    case "contact": {
      // cello contact add <pubkey> [--agent <name>] | remove <pubkey> [--agent <name>] | list [--agent <name>]
      const args = process.argv.slice(3);
      const agentIdx = args.indexOf("--agent");
      const agent = agentIdx !== -1 ? args[agentIdx + 1] : undefined;
      const positional = args.filter((a, i) => !(a === "--agent" || i === agentIdx + 1));
      const [sub, pubkey] = positional;
      if (sub === "add" && pubkey) {
        result = await contactAdd(celloDir, pubkey, agent);
      } else if (sub === "remove" && pubkey) {
        result = await contactRemove(celloDir, pubkey, agent);
      } else if (sub === "list") {
        result = await contactList(celloDir, agent);
      } else {
        result = { exitCode: 1, output: "Usage: cello contact add|remove <pubkey> [--agent <name>] | cello contact list [--agent <name>]" };
      }
      break;
    }
    default:
      // M8B F1: the usage string lists EVERY command (refresh/receipts were missing).
      process.stdout.write(USAGE + "\n");
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
