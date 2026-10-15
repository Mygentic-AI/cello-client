/**
 * Unit and subprocess tests for `@cello-protocol/daemon` `localstorage-guard.ts`.
 *
 * Verifies that:
 *   1. `suppressUnconfiguredLocalStorageWarning` neutralizes a lazy `localStorage` getter without
 *      invoking it when `--localstorage-file` is absent, and preserves it when configured in
 *      `execArgv` or `NODE_OPTIONS`.
 *   2. Importing `core/daemon/src/index.ts`, `core/daemon/src/daemon.ts`, or
 *      `core/daemon/src/document-engine.ts` in a fresh child process (where `yjs` -> `lib0/storage.js`
 *      evaluates `typeof localStorage !== "undefined"`) emits zero `ExperimentalWarning` on `stderr`.
 */

import { describe, it, expect } from "vitest";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { suppressUnconfiguredLocalStorageWarning } from "../localstorage-guard.js";

function findTsx(): string {
  const isWin = process.platform === "win32";
  const candidates = [
    join(import.meta.dirname, "../../../../node_modules/.bin", isWin ? "tsx.cmd" : "tsx"),
    join(import.meta.dirname, "../../../../node_modules/.pnpm/node_modules/.bin", isWin ? "tsx.cmd" : "tsx"),
    join(import.meta.dirname, "../../node_modules/.bin", isWin ? "tsx.cmd" : "tsx"),
  ];
  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  throw new Error(`tsx not found in candidate paths: ${candidates.join(", ")}`);
}

describe("localstorage-guard (daemon)", () => {
  it("1. neutralizes an unconfigured localStorage getter without invoking it and preserves --localstorage-file", () => {
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

    suppressUnconfiguredLocalStorageWarning({
      target: fakeGlobal,
      execArgv: [],
      env: {},
    });
    expect(getterInvoked).toBe(0);
    expect(Object.getOwnPropertyDescriptor(fakeGlobal, "localStorage")?.get).toBeUndefined();
    expect(fakeGlobal["localStorage"]).toBeUndefined();
    expect(getterInvoked).toBe(0);
  });

  it("2. importing index.ts, daemon.ts, and document-engine.ts in a fresh subprocess emits zero ExperimentalWarning on stderr", () => {
    const tsxPath = findTsx();
    for (const rel of ["../index.ts", "../daemon.ts", "../document-engine.ts"]) {
      const modUrl = new URL(rel, import.meta.url).href;
      const run = spawnSync(
        tsxPath,
        ["-e", `import(${JSON.stringify(modUrl)}).then(() => { void globalThis.localStorage; });`],
        {
          env: { ...process.env },
          shell: process.platform === "win32",
          encoding: "utf8",
        },
      );
      expect(run.status).toBe(0);
      expect(run.stderr).not.toContain("ExperimentalWarning");
      expect(run.stderr).not.toContain("localStorage");
    }
  });
});
