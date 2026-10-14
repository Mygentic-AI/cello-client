/**
 * Node runtime version guard and PATH alignment tests for @cello-protocol/cli.
 *
 * Clauses verified here:
 *   1. Node >= 22 passes `checkNodeRuntime` and prepends `dirname(execPath)` to `env.PATH` when
 *      another directory is currently first on `PATH`, so child `npm` / `npx` / shebang spawns
 *      resolve to the active Node runtime directory rather than an older system Node on `PATH`.
 *   2. When `dirname(execPath)` is already the first entry on `env.PATH`, `env.PATH` is not
 *      duplicated.
 *   3. Node < 22 (e.g. Node 18 or Node 20 picked up via `#!/usr/bin/env node` on a multi-Node
 *      machine) returns `ok: false` with a diagnostic naming the detected version, the exact
 *      `execPath` binary that was invoked, the minimum required Node version (`>=22`), and
 *      actionable PATH / MCP remediation guidance.
 *   4. `enforceNodeRuntime` writes the diagnostic to `stderr` and calls `exit(1)` when `ok: false`,
 *      and neither writes nor exits when `ok: true`.
 */

import { describe, it, expect } from "vitest";
import { delimiter, join } from "node:path";
import { spawnSync } from "node:child_process";
import { checkNodeRuntime, enforceNodeRuntime } from "../node-runtime-guard.js";

describe("node-runtime-guard (CLI)", () => {
  it("1. passes on Node >= 22 and prepends dirname(execPath) to PATH when not already first", () => {
    const env: NodeJS.ProcessEnv = {
      PATH: `/usr/local/bin${delimiter}/usr/bin`,
    };
    const res = checkNodeRuntime({
      version: "24.21.0",
      execPath: "/opt/private-node-v24/bin/node",
      env,
    });

    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.major).toBe(24);
      expect(res.pathPrepended).toBe(true);
    }
    expect(env.PATH).toBe(`/opt/private-node-v24/bin${delimiter}/usr/local/bin${delimiter}/usr/bin`);
  });

  it("2. does not duplicate dirname(execPath) when it is already first on PATH", () => {
    const initialPath = `/opt/private-node-v24/bin${delimiter}/usr/bin`;
    const env: NodeJS.ProcessEnv = { PATH: initialPath };
    const res = checkNodeRuntime({
      version: "v22.14.0",
      execPath: "/opt/private-node-v24/bin/node",
      env,
    });

    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.major).toBe(22);
      expect(res.pathPrepended).toBe(false);
    }
    expect(env.PATH).toBe(initialPath);
  });

  it("3. refuses Node < 22 and names both version and execPath with remediation guidance", () => {
    const env: NodeJS.ProcessEnv = { PATH: "/usr/bin" };
    const res = checkNodeRuntime({
      version: "20.11.1",
      execPath: "/usr/bin/node",
      env,
    });

    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.major).toBe(20);
      expect(res.version).toBe("20.11.1");
      expect(res.execPath).toBe("/usr/bin/node");
      expect(res.message).toContain("20.11.1");
      expect(res.message).toContain("/usr/bin/node");
      expect(res.message).toContain(">=22");
      expect(res.message).toContain("PATH");
    }
  });

  it("4. enforceNodeRuntime writes to stderr and exits 1 on unsupported Node, and is silent on supported Node", () => {
    const stderrLines: string[] = [];
    const exitCodes: number[] = [];

    enforceNodeRuntime({
      version: "18.19.0",
      execPath: "/usr/local/old-node/bin/node",
      env: { PATH: "/usr/local/old-node/bin" },
      writeStderr: (s) => stderrLines.push(s),
      exit: (code) => exitCodes.push(code),
    });

    expect(exitCodes).toEqual([1]);
    expect(stderrLines).toHaveLength(1);
    expect(stderrLines[0]).toContain("/usr/local/old-node/bin/node");
    expect(stderrLines[0]).toContain("18.19.0");

    const okLines: string[] = [];
    const okExits: number[] = [];
    enforceNodeRuntime({
      version: "24.21.0",
      execPath: "/opt/node24/bin/node",
      env: { PATH: "/usr/bin" },
      writeStderr: (s) => okLines.push(s),
      exit: (code) => okExits.push(code),
    });

    expect(okExits).toEqual([]);
    expect(okLines).toEqual([]);
  });

  it("5. dist/bin/cello.js invokes enforceNodeRuntime at startup before dispatching", () => {
    const binPath = join(import.meta.dirname, "../../dist/bin/cello.js");
    const run = spawnSync(process.execPath, [binPath, "--version"], {
      env: { ...process.env, CELLO_MIN_NODE_MAJOR: "999" },
      encoding: "utf8",
    });

    expect(run.status).toBe(1);
    expect(run.stderr).toContain(process.versions.node);
    expect(run.stderr).toContain(process.execPath);
    expect(run.stderr).toContain(">=999");
  });
});
