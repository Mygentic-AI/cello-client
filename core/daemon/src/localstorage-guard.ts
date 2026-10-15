/**
 * Side-effecting initializer that neutralizes Node 25+'s unconfigured `globalThis.localStorage`
 * getter before `yjs` (`lib0/storage.js`) is imported.
 *
 * In Node 25+, reading `globalThis.localStorage` (including `typeof localStorage !== "undefined"`
 * inside `lib0/storage.js:43`) triggers `node:internal/webstorage`, which prints
 * `ExperimentalWarning: localStorage is not available because --localstorage-file was not provided.`
 * to `stderr` whenever `--localstorage-file` is not set.
 */

export interface SuppressLocalStorageWarningOptions {
  target?: object;
  execArgv?: readonly string[];
  env?: NodeJS.ProcessEnv;
}

export function suppressUnconfiguredLocalStorageWarning(
  opts?: SuppressLocalStorageWarningOptions,
): void {
  const target = opts?.target ?? globalThis;
  const execArgv = opts?.execArgv ?? process.execArgv;
  const env = opts?.env ?? process.env;
  const nodeOptions = env["NODE_OPTIONS"] ?? "";

  const hasLocalStorageFlag =
    execArgv.some((arg) => arg === "--localstorage-file" || arg.startsWith("--localstorage-file=")) ||
    /(?:^|\s)--localstorage-file(?:=|\s|$)/.test(nodeOptions);
  if (hasLocalStorageFlag) return;

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

suppressUnconfiguredLocalStorageWarning();
