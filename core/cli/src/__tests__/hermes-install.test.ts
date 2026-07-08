/**
 * HERMES-001 — `cello install hermes` installer tests.
 *
 * The installer scaffolds the CELLO platform-adapter plugin into a Hermes Agent home
 * directory, binds the agent name via the Hermes env file, and registers the plugin +
 * MCP server through Hermes' own CLI surfaces (`hermes plugins enable`, `hermes mcp add`)
 * — never by hand-editing config.yaml.
 *
 * Design source: trustless-cello docs/planning/discussion_logs/
 * 2026-07-09_1915_hermes-agent-integration-plan.md §3–§5.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { installHermes, type ExecFn } from "../hermes/install-hermes.js";
import { KNOWN_COMMANDS, USAGE, helpForCommand, checkArgs } from "../cli-args.js";

let hermesHome: string;
let execCalls: Array<{ cmd: string; args: string[] }>;

/** Fake `hermes` CLI that records invocations and succeeds (mcp list shows cello). */
const okExec: ExecFn = async (cmd, args) => {
  execCalls.push({ cmd, args });
  const stdout = args[0] === "mcp" && args[1] === "list" ? "  cello   stdio   enabled\n" : "";
  return { code: 0, stdout, stderr: "" };
};

beforeEach(() => {
  hermesHome = mkdtempSync(join(tmpdir(), "hermes-home-"));
  execCalls = [];
});

afterEach(() => {
  rmSync(hermesHome, { recursive: true, force: true });
});

describe("installHermes — argument and environment validation", () => {
  it("fails with guidance when agentName is empty", async () => {
    const res = await installHermes({ agentName: "", hermesHome, exec: okExec });
    expect(res.exitCode).toBe(1);
    expect(res.output).toContain("--agent");
  });

  it("fails loudly when the Hermes home directory does not exist", async () => {
    const missing = join(hermesHome, "nope");
    const res = await installHermes({ agentName: "alice", hermesHome: missing, exec: okExec });
    expect(res.exitCode).toBe(1);
    expect(res.output).toContain(missing);
    expect(execCalls).toHaveLength(0);
  });
});

describe("installHermes — successful scaffold", () => {
  it("writes the plugin package, skill, env binding, and registers via the hermes CLI", async () => {
    const res = await installHermes({ agentName: "alice", hermesHome, exec: okExec });
    expect(res.exitCode).toBe(0);

    // Plugin package: manifest + adapter module
    const pluginYaml = readFileSync(join(hermesHome, "plugins", "cello", "plugin.yaml"), "utf-8");
    expect(pluginYaml).toContain("name: cello");
    expect(pluginYaml).toContain("kind: platform");

    const initPy = readFileSync(join(hermesHome, "plugins", "cello", "__init__.py"), "utf-8");
    expect(initPy).toContain("def register(ctx");
    expect(initPy).toContain("cello_use_agent");
    expect(initPy).toContain("CELLO_AGENT_NAME");
    // Reply-side correctness requirements from the plan (§3.2) must reach the LLM
    expect(initPy).toContain("session_not_current");
    expect(initPy).toContain("[SILENT]");

    // Skill
    const skill = readFileSync(join(hermesHome, "skills", "cello-bridge-setup", "SKILL.md"), "utf-8");
    expect(skill).toContain("name: cello-bridge-setup");
    expect(skill).toContain("cello install hermes");

    // Agent binding in the Hermes env file
    const env = readFileSync(join(hermesHome, ".env"), "utf-8");
    expect(env).toContain("CELLO_AGENT_NAME=alice");

    // Registered through Hermes' own CLI, not YAML editing — and VERIFIED, because
    // `hermes mcp add` can cancel at its interactive prompt while still exiting 0.
    expect(execCalls).toEqual([
      { cmd: "hermes", args: ["plugins", "enable", "cello"] },
      {
        cmd: "hermes",
        args: [
          "mcp", "add", "cello",
          "--command", "npx",
          "--args", "--yes", "@cello-protocol/connect@latest",
        ],
      },
      { cmd: "hermes", args: ["mcp", "list"] },
    ]);

    // Next step surfaced to the operator
    expect(res.output).toContain("hermes gateway restart");
  });

  it("preserves unrelated .env lines and replaces an existing CELLO_AGENT_NAME", async () => {
    writeFileSync(join(hermesHome, ".env"), "OPENAI_API_KEY=sk-test\nCELLO_AGENT_NAME=old-agent\nOTHER=1\n");
    const res = await installHermes({ agentName: "bob", hermesHome, exec: okExec });
    expect(res.exitCode).toBe(0);

    const env = readFileSync(join(hermesHome, ".env"), "utf-8");
    expect(env).toContain("OPENAI_API_KEY=sk-test");
    expect(env).toContain("OTHER=1");
    expect(env).toContain("CELLO_AGENT_NAME=bob");
    expect(env).not.toContain("old-agent");
    // exactly one binding line
    expect(env.split("\n").filter((l) => l.startsWith("CELLO_AGENT_NAME=")).length).toBe(1);
  });

  it("is idempotent — a second run overwrites cleanly and keeps one env binding", async () => {
    await installHermes({ agentName: "alice", hermesHome, exec: okExec });
    const res = await installHermes({ agentName: "alice", hermesHome, exec: okExec });
    expect(res.exitCode).toBe(0);
    const env = readFileSync(join(hermesHome, ".env"), "utf-8");
    expect(env.split("\n").filter((l) => l.startsWith("CELLO_AGENT_NAME=")).length).toBe(1);
    expect(existsSync(join(hermesHome, "plugins", "cello", "__init__.py"))).toBe(true);
  });
});

describe("installHermes — hermes CLI failure paths", () => {
  it("fails loud with the manual commands when the hermes CLI is missing", async () => {
    const enoentExec: ExecFn = async () => {
      throw Object.assign(new Error("spawn hermes ENOENT"), { code: "ENOENT" });
    };
    const res = await installHermes({ agentName: "alice", hermesHome, exec: enoentExec });
    expect(res.exitCode).toBe(1);
    // Files were still scaffolded (the write half succeeded)…
    expect(existsSync(join(hermesHome, "plugins", "cello", "__init__.py"))).toBe(true);
    // …and the operator gets the exact commands to finish by hand.
    expect(res.output).toContain("hermes plugins enable cello");
    expect(res.output).toContain("hermes mcp add cello");
  });

  it("fails loud when a hermes command exits non-zero, surfacing its stderr", async () => {
    const failExec: ExecFn = async (cmd, args) => {
      execCalls.push({ cmd, args });
      if (args[0] === "mcp") return { code: 2, stdout: "", stderr: "boom: bad flag" };
      return { code: 0, stdout: "", stderr: "" };
    };
    const res = await installHermes({ agentName: "alice", hermesHome, exec: failExec });
    expect(res.exitCode).toBe(1);
    expect(res.output).toContain("boom: bad flag");
  });

  it("fails loud when mcp add exits 0 but the server never lands in mcp list", async () => {
    // The real-world trap: `hermes mcp add` prints "Cancelled." at its interactive
    // prompt (EOF on stdin) and still exits 0. Only verification catches it.
    const cancelledExec: ExecFn = async (cmd, args) => {
      execCalls.push({ cmd, args });
      if (args[0] === "mcp" && args[1] === "list") {
        return { code: 0, stdout: "  No MCP servers configured.\n", stderr: "" };
      }
      return { code: 0, stdout: "Cancelled.", stderr: "" };
    };
    const res = await installHermes({ agentName: "alice", hermesHome, exec: cancelledExec });
    expect(res.exitCode).toBe(1);
    expect(res.output).toContain("does not show a 'cello' server");
  });
});

describe("cli-args — install command surface", () => {
  it("install is a known command and appears in USAGE", () => {
    expect(KNOWN_COMMANDS.has("install" as never)).toBe(true);
    expect(USAGE).toContain("install");
  });

  it("help for install documents the hermes target and flags", () => {
    const help = helpForCommand("install");
    expect(help).toContain("hermes");
    expect(help).toContain("--agent");
    expect(help).toContain("--hermes-home");
  });

  it("checkArgs accepts install's flags and rejects unknown ones", () => {
    expect(checkArgs("install", ["hermes", "--agent", "alice"])).toEqual({ kind: "ok" });
    expect(checkArgs("install", ["hermes", "--hermes-home", "/tmp/x"])).toEqual({ kind: "ok" });
    expect(checkArgs("install", ["hermes", "--bogus"])).toEqual({ kind: "unknown_flag", flag: "--bogus" });
  });
});
