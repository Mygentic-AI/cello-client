/**
 * Node runtime version guard and PATH alignment tests for @cello-protocol/connect (cello-mcp).
 */

import { describe, it, expect } from "vitest";
import { delimiter, join } from "node:path";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import {
  checkNodeRuntime,
  enforceNodeRuntime,
  suppressUnconfiguredLocalStorageWarning,
} from "../node-runtime-guard.js";

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

describe("node-runtime-guard (MCP adapter)", () => {
  it("1. passes on Node >= 22 (including boundary 22.0.0) and prepends dirname(execPath) to PATH (including empty PATH)", () => {
    const env: NodeJS.ProcessEnv = { PATH: `/usr/bin` };
    const res = checkNodeRuntime({
      version: "24.21.0",
      execPath: "/home/user/.nvm/versions/node/v24.21.0/bin/node",
      env,
    });

    expect(res).toEqual({ ok: true });
    expect(env.PATH).toBe(`/home/user/.nvm/versions/node/v24.21.0/bin${delimiter}/usr/bin`);

    const emptyEnv: NodeJS.ProcessEnv = {};
    const boundaryRes = checkNodeRuntime({
      version: "22.0.0",
      execPath: "/opt/node22/bin/node",
      env: emptyEnv,
    });
    expect(boundaryRes).toEqual({ ok: true });
    expect(emptyEnv.PATH).toBe("/opt/node22/bin");
  });

  it("2. does not duplicate dirname(execPath) when it is already first on PATH", () => {
    const initialPath = `/opt/node22/bin${delimiter}/usr/bin`;
    const env: NodeJS.ProcessEnv = { PATH: initialPath };
    const res = checkNodeRuntime({
      version: "v22.5.0",
      execPath: "/opt/node22/bin/node",
      env,
    });

    expect(res).toEqual({ ok: true });
    expect(env.PATH).toBe(initialPath);
  });

  it("3. refuses Node < 22 and unparseable versions, exiting 1 with stderr diagnostic naming execPath and version", () => {
    const stderrLines: string[] = [];
    const exitCodes: number[] = [];

    enforceNodeRuntime({
      version: "20.10.0",
      execPath: "/usr/bin/node",
      env: { PATH: "/usr/bin" },
      writeStderr: (s) => stderrLines.push(s),
      exit: (code) => exitCodes.push(code),
    });

    expect(exitCodes).toEqual([1]);
    expect(stderrLines).toHaveLength(1);
    expect(stderrLines[0]).toContain("20.10.0");
    expect(stderrLines[0]).toContain("/usr/bin/node");
    expect(stderrLines[0]).toContain(">=22");

    const badRes = checkNodeRuntime({
      version: "invalid",
      execPath: "/usr/bin/node",
      env: { PATH: "/usr/bin" },
    });
    expect(badRes.ok).toBe(false);
    if (!badRes.ok) {
      expect(badRes.message).toContain("invalid");
      expect(badRes.message).toContain("/usr/bin/node");
    }
  });

  it("4. src/bin/cello-mcp.ts invokes enforceNodeRuntime via first import before --version", () => {
    const tsxPath = findTsx();
    const binPath = join(import.meta.dirname, "../bin/cello-mcp.ts");
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

  it("5. suppressUnconfiguredLocalStorageWarning neutralizes an unconfigured localStorage getter without invoking it and preserves --localstorage-file", () => {
    let getterInvoked = 0;
    const fakeGlobal: Record<string, unknown> = {};
    Object.defineProperty(fakeGlobal, "localStorage", {
      get() {
        getterInvoked += 1;
        return undefined;
      },
      configurable: true,
      enumerable: true,
    });

    suppressUnconfiguredLocalStorageWarning({
      target: fakeGlobal,
      execArgv: ["--localstorage-file=/tmp/store"],
      env: {},
    });
    expect(Object.getOwnPropertyDescriptor(fakeGlobal, "localStorage")?.get).toBeTypeOf("function");

    suppressUnconfiguredLocalStorageWarning({
      target: fakeGlobal,
      execArgv: [],
      env: { NODE_OPTIONS: "--localstorage-file /tmp/store" },
    });
    expect(Object.getOwnPropertyDescriptor(fakeGlobal, "localStorage")?.get).toBeTypeOf("function");
    expect(getterInvoked).toBe(0);

    enforceNodeRuntime({
      version: "24.21.0",
      execPath: "/opt/node24/bin/node",
      target: fakeGlobal,
      execArgv: [],
      env: {},
    });
    expect(getterInvoked).toBe(0);
    expect(Object.getOwnPropertyDescriptor(fakeGlobal, "localStorage")?.get).toBeUndefined();
    expect(fakeGlobal["localStorage"]).toBeUndefined();
    expect(getterInvoked).toBe(0);

    const tsxPath = findTsx();
    const initUrl = new URL("../node-runtime-guard-init.ts", import.meta.url).href;
    const initRun = spawnSync(
      tsxPath,
      ["-e", `import(${JSON.stringify(initUrl)}).then(() => { void globalThis.localStorage; });`],
      {
        env: { ...process.env },
        shell: process.platform === "win32",
        encoding: "utf8",
      },
    );
    expect(initRun.status).toBe(0);
    expect(initRun.stderr).not.toContain("ExperimentalWarning");
    expect(initRun.stderr).not.toContain("localStorage");
  });
});
