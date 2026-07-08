/**
 * HERMES-001 — `cello install hermes`: wire the local CELLO daemon into a Hermes
 * Agent installation.
 *
 * What it does (design: trustless-cello 2026-07-09_1915_hermes-agent-integration-plan.md §5):
 *   1. Scaffolds the platform-adapter plugin into $HERMES_HOME/plugins/cello/
 *      (plugin.yaml + __init__.py — a pure-stdlib Python IPC client, no subprocess).
 *   2. Drops the cello-bridge-setup skill into $HERMES_HOME/skills/.
 *   3. Binds the agent: writes CELLO_AGENT_NAME=<agent> into $HERMES_HOME/.env
 *      (replace-or-append; every other line preserved byte-for-byte).
 *   4. Registers through Hermes' OWN CLI surfaces — `hermes plugins enable cello` and
 *      `hermes mcp add cello …` — never by hand-editing config.yaml, so Hermes owns
 *      its config format.
 *
 * Never edits anything outside $HERMES_HOME. Idempotent: re-running upgrades the
 * scaffolded files in place and keeps exactly one CELLO_AGENT_NAME line.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";

import { HERMES_PLUGIN_YAML, HERMES_PLUGIN_INIT_PY, HERMES_SKILL_MD } from "./assets.js";

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

export type ExecFn = (cmd: string, args: string[]) => Promise<ExecResult>;

export interface InstallHermesOptions {
  agentName: string;
  /** Defaults to $HERMES_HOME, falling back to ~/.hermes. */
  hermesHome?: string;
  /** Injectable for tests; defaults to a spawn-based runner. */
  exec?: ExecFn;
}

/** The two Hermes CLI registrations the installer performs (also printed as the
 * manual fallback when the `hermes` binary cannot be run). */
const HERMES_COMMANDS: ReadonlyArray<ReadonlyArray<string>> = [
  ["plugins", "enable", "cello"],
  ["mcp", "add", "cello", "--command", "npx", "--args", "--yes", "@cello-protocol/connect@latest"],
];

const defaultExec: ExecFn = (cmd, args) =>
  new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"] });
    // `hermes mcp add` interactively asks "Enable all N tools? [Y/n/select]" via
    // plain input() — answer yes. (A closed stdin reads as EOF → "Cancelled." with
    // exit 0, which is why installHermes also VERIFIES the registration afterward
    // instead of trusting the exit code.)
    child.stdin.write("Y\n");
    child.stdin.end();
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf-8")));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString("utf-8")));
    child.on("error", reject); // e.g. ENOENT — hermes not on PATH
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });

/** Replace-or-append KEY=value in an env file, preserving every other line. */
function upsertEnvLine(envPath: string, key: string, value: string): void {
  const line = `${key}=${value}`;
  let lines: string[] = [];
  if (existsSync(envPath)) {
    lines = readFileSync(envPath, "utf-8").split("\n");
  }
  let replaced = false;
  lines = lines.map((l) => {
    if (l.startsWith(`${key}=`)) {
      replaced = true;
      return line;
    }
    return l;
  });
  if (!replaced) {
    // Drop a single trailing empty line before appending so we don't grow blank gaps.
    if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
    lines.push(line);
  }
  writeFileSync(envPath, lines.join("\n") + (lines[lines.length - 1] === "" ? "" : "\n"));
}

export async function installHermes(
  opts: InstallHermesOptions,
): Promise<{ exitCode: number; output: string }> {
  const agentName = (opts.agentName ?? "").trim();
  if (!agentName) {
    return {
      exitCode: 1,
      output:
        "Missing agent name. Usage: cello install hermes --agent <name> [--hermes-home <path>]\n" +
        "The agent must be a local CELLO agent (see 'cello status' for the list).",
    };
  }

  const hermesHome = opts.hermesHome || process.env.HERMES_HOME || join(homedir(), ".hermes");
  if (!existsSync(hermesHome)) {
    return {
      exitCode: 1,
      output:
        `Hermes home not found at ${hermesHome}.\n` +
        "Install Hermes Agent first (https://hermes-agent.nousresearch.com), or pass --hermes-home <path> " +
        "if it lives elsewhere.",
    };
  }

  const exec = opts.exec ?? defaultExec;
  const out: string[] = [];

  // 1. Plugin package
  const pluginDir = join(hermesHome, "plugins", "cello");
  mkdirSync(pluginDir, { recursive: true });
  writeFileSync(join(pluginDir, "plugin.yaml"), HERMES_PLUGIN_YAML);
  writeFileSync(join(pluginDir, "__init__.py"), HERMES_PLUGIN_INIT_PY);
  out.push(`Wrote plugin: ${pluginDir}/{plugin.yaml,__init__.py}`);

  // 2. Skill
  const skillDir = join(hermesHome, "skills", "cello-bridge-setup");
  mkdirSync(skillDir, { recursive: true });
  writeFileSync(join(skillDir, "SKILL.md"), HERMES_SKILL_MD);
  out.push(`Wrote skill:  ${skillDir}/SKILL.md`);

  // 3. Agent binding
  const envPath = join(hermesHome, ".env");
  upsertEnvLine(envPath, "CELLO_AGENT_NAME", agentName);
  out.push(`Bound agent:  CELLO_AGENT_NAME=${agentName} (${envPath})`);

  // 4. Register through Hermes' own CLI. A failure here is loud: the files are in
  // place, so we print exactly what remains to be run by hand.
  for (const args of HERMES_COMMANDS) {
    let result: ExecResult;
    try {
      result = await exec("hermes", [...args]);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      out.push(
        `\nCould not run the 'hermes' CLI (${msg}).`,
        "The CELLO files are installed, but Hermes still needs these two commands run manually:",
        "  hermes plugins enable cello",
        "  hermes mcp add cello --command npx --args --yes @cello-protocol/connect@latest",
        "Then restart the gateway: hermes gateway restart",
      );
      return { exitCode: 1, output: out.join("\n") };
    }
    if (result.code !== 0) {
      out.push(
        `\n'hermes ${args.join(" ")}' failed (exit ${result.code}):`,
        (result.stderr || result.stdout).trim(),
        "Fix the error above and re-run 'cello install hermes' (it is idempotent).",
      );
      return { exitCode: 1, output: out.join("\n") };
    }
    out.push(`Ran:          hermes ${args.join(" ")}`);
  }

  // Verify the MCP registration actually landed: `hermes mcp add` can print
  // "Cancelled." and still exit 0 (e.g. when its interactive prompt hits EOF),
  // so the exit code alone proves nothing.
  try {
    const list = await exec("hermes", ["mcp", "list"]);
    if (!list.stdout.includes("cello")) {
      out.push(
        "",
        "'hermes mcp add' reported success but 'hermes mcp list' does not show a 'cello' server.",
        "Run this manually and answer Y at the tool prompt:",
        "  hermes mcp add cello --command npx --args --yes @cello-protocol/connect@latest",
      );
      return { exitCode: 1, output: out.join("\n") };
    }
  } catch {
    // hermes CLI vanished between calls — vanishingly unlikely; the add above succeeded.
  }
  out.push("Verified:     'cello' present in hermes mcp list");

  out.push(
    "",
    "CELLO bridge installed. Next step: restart the gateway so Hermes loads the plugin:",
    "  hermes gateway restart",
    "Then verify from a Hermes chat by calling the cello_status MCP tool.",
  );
  return { exitCode: 0, output: out.join("\n") };
}
