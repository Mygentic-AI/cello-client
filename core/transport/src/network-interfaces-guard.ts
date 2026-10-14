/**
 * Guarded `os.networkInterfaces()` wrapper for restricted userlands (Android 10+ / Termux / PRoot).
 *
 * On Android 10+, SELinux blocks Netlink `RTM_GETADDR` sockets in unprivileged processes, so
 * libuv's `uv_interface_addresses` throws `ERR_SYSTEM_ERROR` (EACCES, errno -13). `@libp2p/utils`
 * (`get-thin-waist-addresses`) calls `os.networkInterfaces()` with no try/catch whenever a TCP
 * listener expands a wildcard address (`/ip4/0.0.0.0/tcp/0`), crashing the daemon during
 * standing-receiver initialization.
 *
 * On macOS, standard Linux, and Windows, `os.networkInterfaces()` succeeds and its native result is
 * returned untouched. Only when the underlying call throws does this guard catch the error, report
 * the upstream cause (`code`, `errno`, `syscall`, `message`) to `onFallback` once per distinct
 * error code, and return a loopback interface dictionary (`127.0.0.1` and `::1`) so wildcard listen
 * expansion completes and the node operates over relay transport.
 */

import os from "node:os";
import { syncBuiltinESMExports } from "node:module";

export interface NetworkInterfacesFallbackEvent {
  readonly code: string;
  readonly errno: number | undefined;
  readonly syscall: string | undefined;
  readonly message: string;
}

export interface SafeNetworkInterfacesGuardOptions {
  /** Called once per distinct error code when `os.networkInterfaces()` throws and falls back. */
  onFallback?: (event: NetworkInterfacesFallbackEvent) => void;
  /** Test seam: override the underlying `networkInterfaces` implementation. */
  impl?: () => NodeJS.Dict<os.NetworkInterfaceInfo[]>;
}

const realNetworkInterfaces: () => NodeJS.Dict<os.NetworkInterfaceInfo[]> =
  os.networkInterfaces.bind(os);

let installed = false;
let currentImpl: () => NodeJS.Dict<os.NetworkInterfaceInfo[]> = realNetworkInterfaces;
let currentOnFallback: ((event: NetworkInterfacesFallbackEvent) => void) | undefined;
const reportedCodes = new Set<string>();

function buildLoopbackInterfaces(): NodeJS.Dict<os.NetworkInterfaceInfo[]> {
  return {
    lo: [
      {
        address: "127.0.0.1",
        netmask: "255.0.0.0",
        family: "IPv4",
        mac: "00:00:00:00:00:00",
        internal: true,
        cidr: "127.0.0.1/8",
      },
      {
        address: "::1",
        netmask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        family: "IPv6",
        mac: "00:00:00:00:00:00",
        internal: true,
        cidr: "::1/128",
        scopeid: 0,
      },
    ],
  };
}

function guardedNetworkInterfaces(): NodeJS.Dict<os.NetworkInterfaceInfo[]> {
  try {
    return currentImpl();
  } catch (err: unknown) {
    const sysErr = err as NodeJS.ErrnoException | null;
    const code = typeof sysErr?.code === "string" ? sysErr.code : "UNKNOWN_OS_ERROR";
    const errno = typeof sysErr?.errno === "number" ? sysErr.errno : undefined;
    const syscall = typeof sysErr?.syscall === "string" ? sysErr.syscall : undefined;
    const message = err instanceof Error ? err.message : String(err);

    if (currentOnFallback && !reportedCodes.has(code)) {
      reportedCodes.add(code);
      try {
        currentOnFallback({ code, errno, syscall, message });
      } catch {
        // A logger failure must not re-crash the networkInterfaces caller.
      }
    }
    return buildLoopbackInterfaces();
  }
}

/**
 * Install the guarded `os.networkInterfaces` wrapper idempotently.
 *
 * If called again with `onFallback` or `impl`, updates the active handler without double-wrapping
 * `os.networkInterfaces`.
 */
export function installSafeNetworkInterfacesGuard(
  opts?: SafeNetworkInterfacesGuardOptions,
): void {
  if (opts?.impl !== undefined) {
    currentImpl = opts.impl;
    reportedCodes.clear();
  }
  if (opts?.onFallback !== undefined) {
    currentOnFallback = opts.onFallback;
  }
  if (!installed) {
    os.networkInterfaces = guardedNetworkInterfaces;
    syncBuiltinESMExports();
    installed = true;
  }
}

/** Restore the original `os.networkInterfaces` binding (for unit tests only). */
export function uninstallSafeNetworkInterfacesGuardForTest(): void {
  currentImpl = realNetworkInterfaces;
  currentOnFallback = undefined;
  reportedCodes.clear();
  if (installed) {
    os.networkInterfaces = realNetworkInterfaces;
    syncBuiltinESMExports();
    installed = false;
  }
}
