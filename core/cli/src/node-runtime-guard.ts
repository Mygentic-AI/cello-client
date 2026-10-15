/**
 * Node runtime version guard and PATH alignment for the `cello` CLI binary.
 *
 * When a host has multiple Node.js installations (for example, a system Node 18/20 in `/usr/bin`
 * and a private Node 22/24 installation), two failure modes occur:
 *   1. `#!/usr/bin/env node` resolves to the older Node earlier on `PATH`.
 *   2. Even when `cello` is invoked explicitly via `/path/to/node24/bin/node /path/to/cello`,
 *      subsequent child spawns that resolve `npm`, `npx`, or `#!/usr/bin/env node` via `PATH`
 *      hit the older directory on `PATH` unless `dirname(process.execPath)` is first on `PATH`.
 *
 * `checkNodeRuntime` validates the running Node major version (default `>= 22`) and prepends
 * `dirname(execPath)` to `env.PATH` when it is not already first.
 */

import { dirname, delimiter } from "node:path";

export const DEFAULT_MIN_NODE_MAJOR = 22;

export interface CheckNodeRuntimeOptions {
  version?: string;
  execPath?: string;
  env?: NodeJS.ProcessEnv;
  minMajor?: number;
}

export type CheckNodeRuntimeResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly message: string };

export function checkNodeRuntime(opts?: CheckNodeRuntimeOptions): CheckNodeRuntimeResult {
  const rawVersion = (opts?.version ?? process.versions.node).replace(/^v/i, "");
  const execPath = opts?.execPath ?? process.execPath;
  const env = opts?.env ?? process.env;
  const envMin = Number(env["CELLO_MIN_NODE_MAJOR"]);
  const minMajor =
    opts?.minMajor ?? (Number.isInteger(envMin) && envMin > 0 ? envMin : DEFAULT_MIN_NODE_MAJOR);

  const major = Number.parseInt(rawVersion.split(".")[0] ?? "", 10);
  if (!Number.isFinite(major) || major < minMajor) {
    const message =
      `Unsupported Node.js runtime v${rawVersion} at ${execPath} (CELLO requires Node.js >=${minMajor}).\n` +
      `If you have a newer Node.js installed on this machine, place its bin directory first on PATH:\n` +
      `  export PATH="<path-to-node-${minMajor}+-bin>:$PATH"`;
    return { ok: false, message };
  }

  const execDir = dirname(execPath);
  const currentPath = env["PATH"] ?? "";
  const segments = currentPath.length > 0 ? currentPath.split(delimiter) : [];
  if (segments[0] !== execDir) {
    env["PATH"] = currentPath.length > 0 ? `${execDir}${delimiter}${currentPath}` : execDir;
  }

  return { ok: true };
}

export interface SuppressLocalStorageWarningOptions {
  target?: object;
  execArgv?: readonly string[];
  env?: NodeJS.ProcessEnv;
}

/**
 * Node 25+ defines a lazy getter on `globalThis.localStorage` (`node:internal/webstorage`) that
 * emits `ExperimentalWarning: localStorage is not available because --localstorage-file was not
 * provided.` the first time any dependency (such as `lib0/storage.js` via `yjs`) evaluates
 * `typeof localStorage !== "undefined"`.
 *
 * When `--localstorage-file` is not configured in `execArgv` or `NODE_OPTIONS`, replace the
 * lazy getter on `globalThis` with `value: undefined` without invoking the getter.
 */
export function suppressUnconfiguredLocalStorageWarning(
  opts?: SuppressLocalStorageWarningOptions,
): void {
  const target = opts?.target ?? globalThis;
  const execArgv = opts?.execArgv ?? process.execArgv;
  const env = opts?.env ?? process.env;
  const nodeOptions = env["NODE_OPTIONS"] ?? "";

  const hasFlag =
    execArgv.some((arg) => arg === "--localstorage-file" || arg.startsWith("--localstorage-file=")) ||
    /(?:^|\s)--localstorage-file(?:=|\s|$)/.test(nodeOptions);
  if (hasFlag) return;

  const desc = Object.getOwnPropertyDescriptor(target, "localStorage");
  if (desc && typeof desc.get === "function" && desc.configurable) {
    Object.defineProperty(target, "localStorage", {
      value: undefined,
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }
}

export interface EnforceNodeRuntimeOptions extends CheckNodeRuntimeOptions {
  writeStderr?: (text: string) => void;
  exit?: (code: number) => void;
}

export function enforceNodeRuntime(opts?: EnforceNodeRuntimeOptions): void {
  suppressUnconfiguredLocalStorageWarning({ env: opts?.env });
  const res = checkNodeRuntime(opts);
  if (!res.ok) {
    const write = opts?.writeStderr ?? ((s: string) => process.stderr.write(s));
    const exit = opts?.exit ?? ((c: number) => process.exit(c));
    write(`${res.message}\n`);
    exit(1);
  }
}
