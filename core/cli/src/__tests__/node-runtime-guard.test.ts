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
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { checkNodeRuntime, enforceNodeRuntime } from "../node-runtime-guard.js";

function findTsx(): string {
  const isWin = process.platform === "win32";
  const candidates = [
    join(import.meta.dirname, "../../../../node_modules/.bin", isWin ? "tsx.cmd" : "tsx"),
    join(import.meta.dirname, "../../../../node_modules/.pnpm/node_modules/.bin", isWin ? "tsx.cmd" : "tsx"),
    join(import.meta.dirname, "../../../daemon/node_modules/.bin", isWin ? "tsx.cmd" : "tsx"),
  ];
  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  throw new Error(`tsx not found in candidate paths: ${candidates.join(", ")}`);
}

describe("node-runtime-guard (CLI)", () => {
  it("1. passes on Node >= 22 and prepends dirname(execPath) to PATH (including when PATH is empty)", () => {
    const env: NodeJS.ProcessEnv = {
      PATH: `/usr/local/bin${delimiter}/usr/bin`,
    };
    const res = checkNodeRuntime({
      version: "24.21.0",
      execPath: "/opt/private-node-v24/bin/node",
      env,
    });

    expect(res).toEqual({ ok: true });
    expect(env.PATH).toBe(`/opt/private-node-v24/bin${delimiter}/usr/local/bin${delimiter}/usr/bin`);

    const emptyEnv: NodeJS.ProcessEnv = {};
    const emptyRes = checkNodeRuntime({
      version: "22.0.0",
      execPath: "/opt/node22/bin/node",
      env: emptyEnv,
    });
    expect(emptyRes).toEqual({ ok: true });
    expect(emptyEnv.PATH).toBe("/opt/node22/bin");
  });

  it("2. does not duplicate dirname(execPath) when it is already first on PATH", () => {
    const initialPath = `/opt/private-node-v24/bin${delimiter}/usr/bin`;
    const env: NodeJS.ProcessEnv = { PATH: initialPath };
    const res = checkNodeRuntime({
      version: "v22.14.0",
      execPath: "/opt/private-node-v24/bin/node",
      env,
    });

    expect(res).toEqual({ ok: true });
    expect(env.PATH).toBe(initialPath);
  });

  it("3. refuses Node < 22 and unparseable versions, naming both version and execPath with guidance", () => {
    const env: NodeJS.ProcessEnv = { PATH: "/usr/bin" };
    const res = checkNodeRuntime({
      version: "20.11.1",
      execPath: "/usr/bin/node",
      env,
    });

    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.message).toContain("20.11.1");
      expect(res.message).toContain("/usr/bin/node");
      expect(res.message).toContain(">=22");
      expect(res.message).toContain("PATH");
    }

    const badVer = checkNodeRuntime({
      version: "invalid",
      execPath: "/usr/local/bin/node",
      env,
    });
    expect(badVer.ok).toBe(false);
    if (!badVer.ok) {
      expect(badVer.message).toContain("invalid");
      expect(badVer.message).toContain("/usr/local/bin/node");
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

  it("5. src/bin/cello.ts invokes enforceNodeRuntime via first import before dispatching", () => {
    const tsxPath = findTsx();
    const binPath = join(import.meta.dirname, "../bin/cello.ts");
    const run = spawnSync(tsxPath, [binPath, "--version"], {
      env: { ...process.env, CELLO_MIN_NODE_MAJOR: "999" },
      shell: process.platform === "win32",
      encoding: "utf8",
    });

    expect(run.status).toBe(1);
    expect(run.stderr).toContain(process.versions.node);
    expect(run.stderr).toContain(process.execPath);
    expect(run.stderr).toContain(">=999");
  });
});
