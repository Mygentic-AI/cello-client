/**
 * HERMES-001 — `cello bridge hermes` installer tests.
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
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { installHermes, type ExecFn } from "../hermes/install-hermes.js";
import { HERMES_POLICY_STEP_MD } from "../hermes/assets.js";
import { KNOWN_COMMANDS, USAGE, helpForCommand, checkArgs } from "../cli-args.js";
import { installHermesDriver } from "./helpers/hermes-python-driver.js";

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

  // ── DOD-HERMES-4: the two per-agent behaviour settings ───────────────────────────────────────

  it("rejects an invalid --delivery-mode before touching the filesystem", async () => {
    // Writing a typo into .env and letting the gateway refuse to start hours later moves the
    // error a long way from the command that caused it. Reject it while the operator is looking.
    const res = await installHermes({
      agentName: "alice", hermesHome, deliveryMode: "notifications", exec: okExec,
    });
    expect(res.exitCode).toBe(1);
    expect(res.output).toContain("--delivery-mode");
    expect(res.output).toContain("channel");
    expect(existsSync(join(hermesHome, ".env"))).toBe(false);
    expect(execCalls).toHaveLength(0);
  });

  it("rejects an invalid --session-scope before touching the filesystem", async () => {
    const res = await installHermes({
      agentName: "alice", hermesHome, sessionScope: "pear", exec: okExec,
    });
    expect(res.exitCode).toBe(1);
    expect(res.output).toContain("--session-scope");
    expect(existsSync(join(hermesHome, ".env"))).toBe(false);
    expect(execCalls).toHaveLength(0);
  });

  it("defaults to explicit + agent when neither flag is given", async () => {
    const res = await installHermes({ agentName: "alice", hermesHome, exec: okExec });
    expect(res.exitCode).toBe(0);
    const env = readFileSync(join(hermesHome, ".env"), "utf-8");
    expect(env).toContain("CELLO_DELIVERY_MODE=explicit");
    expect(env).toContain("CELLO_SESSION_SCOPE=agent");
  });

  it("writes the chosen settings — a support desk gets per-peer isolation", async () => {
    const res = await installHermes({
      agentName: "support-desk", hermesHome, sessionScope: "peer", exec: okExec,
    });
    expect(res.exitCode).toBe(0);
    const env = readFileSync(join(hermesHome, ".env"), "utf-8");
    expect(env).toContain("CELLO_SESSION_SCOPE=peer");
    expect(res.output).toContain("CELLO_SESSION_SCOPE=peer");
  });

  it("re-running WITHOUT a flag resets it to the default — settings never linger invisibly", async () => {
    await installHermes({ agentName: "alice", hermesHome, deliveryMode: "wake", exec: okExec });
    expect(readFileSync(join(hermesHome, ".env"), "utf-8")).toContain("CELLO_DELIVERY_MODE=wake");

    await installHermes({ agentName: "alice", hermesHome, exec: okExec });
    const env = readFileSync(join(hermesHome, ".env"), "utf-8");
    // The alternative — inheriting the previous value — leaves an operator running a mode that
    // appears nowhere in the command they just typed, and upsertEnvLine keeps exactly one line.
    expect(env).toContain("CELLO_DELIVERY_MODE=explicit");
    expect(env).not.toContain("CELLO_DELIVERY_MODE=wake");
  });

  it("preserves unrelated env lines when writing all three settings", async () => {
    writeFileSync(join(hermesHome, ".env"), "TELEGRAM_BOT_TOKEN=secret\nOTHER=1\n");
    await installHermes({ agentName: "alice", hermesHome, exec: okExec });
    const env = readFileSync(join(hermesHome, ".env"), "utf-8");
    expect(env).toContain("TELEGRAM_BOT_TOKEN=secret");
    expect(env).toContain("OTHER=1");
    expect(env).toContain("CELLO_AGENT_NAME=alice");
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
    // 008-POLICY Part G: the policy-writing step ships as a second skill.
    const policySkill = readFileSync(join(hermesHome, "skills", "cello-policy", "SKILL.md"), "utf-8");
    expect(policySkill).toContain("name: cello-policy");
    expect(policySkill).toContain("cello policy approve");
    // One step, two shipped copies: the plugin's Step 7 must say exactly what Hermes gets.
    const pluginSetup = readFileSync(join(import.meta.dirname, "..", "..", "..", "..", "plugins", "cello", "skills", "setup", "SKILL.md"), "utf-8");
    expect(pluginSetup).toContain(HERMES_POLICY_STEP_MD);
    expect(policySkill.endsWith(HERMES_POLICY_STEP_MD)).toBe(true);
    expect(skill).toContain("cello bridge hermes");

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
    expect(KNOWN_COMMANDS.has("bridge" as never)).toBe(true);
    expect(USAGE).toContain("bridge");
  });

  it("help for install documents the hermes target and flags", () => {
    const help = helpForCommand("bridge");
    expect(help).toContain("hermes");
    expect(help).toContain("--agent");
    expect(help).toContain("--hermes-home");
  });

  it("checkArgs accepts install's flags and rejects unknown ones", () => {
    expect(checkArgs("bridge", ["hermes", "--agent", "alice"])).toEqual({ kind: "ok" });
    expect(checkArgs("bridge", ["hermes", "--hermes-home", "/tmp/x"])).toEqual({ kind: "ok" });
    expect(checkArgs("bridge", ["hermes", "--bogus"])).toEqual({ kind: "unknown_flag", flag: "--bogus" });
  });
});

describe("resolveInstallTarget — positional parsing (bin/cello.ts install case)", () => {
  // Mirrors the target-resolution in bin/cello.ts: the "hermes" positional must be
  // found even when a flag and its VALUE precede it (--agent alice hermes).
  function resolveInstallTarget(args: string[]): string | undefined {
    const agentIdx = args.indexOf("--agent");
    const homeIdx = args.indexOf("--hermes-home");
    return args.find(
      (a, i) =>
        !a.startsWith("-") &&
        !(agentIdx !== -1 && i === agentIdx + 1) &&
        !(homeIdx !== -1 && i === homeIdx + 1),
    );
  }

  it("resolves hermes regardless of where the flags sit", () => {
    expect(resolveInstallTarget(["hermes", "--agent", "alice"])).toBe("hermes");
    expect(resolveInstallTarget(["--agent", "alice", "hermes"])).toBe("hermes");
    expect(resolveInstallTarget(["--hermes-home", "/x", "--agent", "alice", "hermes"])).toBe("hermes");
  });

  it("does not mistake a flag value for the target", () => {
    // No positional target given → undefined (installer rejects with usage).
    expect(resolveInstallTarget(["--agent", "alice"])).toBeUndefined();
    expect(resolveInstallTarget(["--hermes-home", "/x"])).toBeUndefined();
  });
});

/**
 * The plugin assets live inside String.raw template literals, so a backtick anywhere in the Python
 * source or its comments silently TERMINATES the template — the file then fails to parse and every
 * hermes test dies at transform time with an error pointing at a comment. Caught twice while
 * writing DOD-HERMES-4; this makes the third time a named failure instead of a puzzle.
 */
describe("hermes assets — template integrity", () => {
  it("the Python adapter contains no backtick — String.raw cannot escape one", async () => {
    // Scoped to the String.raw asset ONLY. HERMES_SKILL_MD is a normal template literal and its
    // markdown code spans are escaped backticks, which are fine; String.raw has no escape at all,
    // so a single backtick there ends the template mid-file.
    const { HERMES_PLUGIN_INIT_PY } = await import("../hermes/assets.js");
    expect(HERMES_PLUGIN_INIT_PY.includes("`")).toBe(false);
  });

  it("multiplexed profile isolation: _env_enablement, CelloAdapter, and _delivery_hint read gateway.platforms._shared.get_scoped_secret instead of leaking os.environ", async () => {
    await installHermesDriver(hermesHome);
    writeFileSync(
      join(hermesHome, "gateway", "platforms", "_shared.py"),
      [
        "import json, os",
        "def get_scoped_secret(name, default=None, *, external_fallback=False):",
        "    raw = os.environ.get('TEST_SCOPED_SECRETS')",
        "    if raw is not None:",
        "        scope = json.loads(raw)",
        "        val = scope.get(name)",
        "        return val if val is not None else default",
        "    val = os.environ.get(name)",
        "    return val if val is not None else default",
        "",
      ].join("\n"),
    );

    const pyProbe = [
      "import json, os",
      "from gateway.config import PlatformConfig",
      "import cello_plugin as m",
      "enabled = m._env_enablement()",
      "adapter_from_seeded = m.CelloAdapter(PlatformConfig(extra=enabled or {}))",
      "adapter_from_empty = m.CelloAdapter(PlatformConfig(extra={}))",
      "hint = m._delivery_hint()",
      "sock = str(m._cello_socket_path())",
      "print(json.dumps({",
      "    'enabled': enabled,",
      "    'seeded_agent': adapter_from_seeded._agent_name,",
      "    'seeded_mode': adapter_from_seeded._delivery_mode,",
      "    'seeded_scope': adapter_from_seeded._session_scope,",
      "    'seeded_notify': adapter_from_seeded._channel_notifications,",
      "    'empty_agent': adapter_from_empty._agent_name,",
      "    'empty_mode': adapter_from_empty._delivery_mode,",
      "    'empty_scope': adapter_from_empty._session_scope,",
      "    'empty_notify': adapter_from_empty._channel_notifications,",
      "    'hint': hint,",
      "    'sock': sock,",
      "}))",
    ].join("\n");

    const runProbe = (extraEnv: Record<string, string>) => {
      const out = execFileSync("python3", ["-c", pyProbe], {
        cwd: hermesHome,
        encoding: "utf8",
        env: {
          ...process.env,
          PYTHONPATH: hermesHome,
          PYTHONDONTWRITEBYTECODE: "1",
          // Simulate default profile in os.environ (Miss_Chelly / channel / agent / on)
          CELLO_AGENT_NAME: "Miss_Chelly",
          CELLO_DELIVERY_MODE: "channel",
          CELLO_SESSION_SCOPE: "agent",
          CELLO_CHANNEL_NOTIFICATIONS: "on",
          CELLO_DIR: "/tmp/default-cello",
          ...extraEnv,
        },
      });
      return JSON.parse(out) as Record<string, unknown>;
    };

    // Case 1: Secondary profile has its own scoped .env (CELLO_LinkedIn) -> must NOT read Miss_Chelly from os.environ.
    const secondaryConfigured = runProbe({
      TEST_SCOPED_SECRETS: JSON.stringify({
        CELLO_AGENT_NAME: "CELLO_LinkedIn",
        CELLO_DELIVERY_MODE: "explicit",
        CELLO_SESSION_SCOPE: "peer",
        CELLO_CHANNEL_NOTIFICATIONS: "off",
        CELLO_DIR: "/tmp/scoped-cello",
      }),
    });
    expect(secondaryConfigured.enabled).toEqual({
      enabled: true,
      agent_name: "CELLO_LinkedIn",
      delivery_mode: "explicit",
      session_scope: "peer",
      channel_notifications: "off",
    });
    expect(secondaryConfigured.seeded_agent).toBe("CELLO_LinkedIn");
    expect(secondaryConfigured.seeded_mode).toBe("explicit");
    expect(secondaryConfigured.seeded_scope).toBe("peer");
    expect(secondaryConfigured.seeded_notify).toBe("off");
    expect(secondaryConfigured.empty_agent).toBe("CELLO_LinkedIn");
    expect(secondaryConfigured.empty_mode).toBe("explicit");
    expect(secondaryConfigured.empty_scope).toBe("peer");
    expect(secondaryConfigured.empty_notify).toBe("off");
    expect(String(secondaryConfigured.hint)).toContain("call cello_send on the session named in the message");
    expect(secondaryConfigured.sock).toBe("/tmp/scoped-cello/daemon.sock");

    // Case 2: Secondary profile has NO CELLO_AGENT_NAME in its scoped .env -> fails closed (None / ""), never borrows Miss_Chelly.
    const secondaryUnconfigured = runProbe({
      TEST_SCOPED_SECRETS: JSON.stringify({}),
    });
    expect(secondaryUnconfigured.enabled).toBeNull();
    expect(secondaryUnconfigured.empty_agent).toBe("");

    // Case 3: Unscoped / standalone fallback (when gateway.platforms._shared is absent) -> reads os.environ.
    rmSync(join(hermesHome, "gateway", "platforms", "_shared.py"));
    const standalone = runProbe({});
    expect(standalone.enabled).toEqual({
      enabled: true,
      agent_name: "Miss_Chelly",
      delivery_mode: "channel",
      session_scope: "agent",
      channel_notifications: "on",
    });
    expect(standalone.seeded_agent).toBe("Miss_Chelly");
  });
});
