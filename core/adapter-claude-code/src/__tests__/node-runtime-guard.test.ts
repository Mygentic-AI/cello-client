/**
 * Node runtime version guard and PATH alignment tests for @cello-protocol/connect (cello-mcp).
 */

import { describe, it, expect } from "vitest";
import { delimiter, join } from "node:path";
import { spawnSync } from "node:child_process";
import { checkNodeRuntime, enforceNodeRuntime } from "../node-runtime-guard.js";

describe("node-runtime-guard (MCP adapter)", () => {
  it("passes on Node >= 22 and prepends dirname(execPath) to PATH", () => {
    const env: NodeJS.ProcessEnv = { PATH: `/usr/bin` };
    const res = checkNodeRuntime({
      version: "24.21.0",
      execPath: "/home/user/.nvm/versions/node/v24.21.0/bin/node",
      env,
    });

    expect(res.ok).toBe(true);
    expect(env.PATH).toBe(`/home/user/.nvm/versions/node/v24.21.0/bin${delimiter}/usr/bin`);
  });

  it("refuses Node < 22 and exits 1 with stderr diagnostic naming execPath and version", () => {
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
  });

  it("dist/bin/cello-mcp.js invokes enforceNodeRuntime at startup before --version", () => {
    const binPath = join(import.meta.dirname, "../../dist/bin/cello-mcp.js");
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
