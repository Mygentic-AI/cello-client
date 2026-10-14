/**
 * Node runtime version guard and PATH alignment for the `cello-mcp` binary.
 *
 * Ensures that when an MCP host invokes `cello-mcp` on a machine with multiple Node installations,
 * an older Node (< 22) picked up from `PATH` fails immediately with a clear diagnostic naming
 * `process.versions.node` and `process.execPath`, and a valid Node runtime places
 * `dirname(process.execPath)` at the front of `PATH`.
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
      `Unsupported Node.js runtime v${rawVersion} at ${execPath} (cello-mcp requires Node.js >=${minMajor}).\n` +
      `Place your Node.js >=${minMajor} bin directory first on PATH or configure your MCP client to launch cello-mcp with the full Node >=${minMajor} binary path.`;
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

export interface EnforceNodeRuntimeOptions extends CheckNodeRuntimeOptions {
  writeStderr?: (text: string) => void;
  exit?: (code: number) => void;
}

export function enforceNodeRuntime(opts?: EnforceNodeRuntimeOptions): void {
  const res = checkNodeRuntime(opts);
  if (!res.ok) {
    const write = opts?.writeStderr ?? ((s: string) => process.stderr.write(s));
    const exit = opts?.exit ?? ((c: number) => process.exit(c));
    write(`${res.message}\n`);
    exit(1);
  }
}
