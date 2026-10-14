/**
 * Android / PRoot `os.networkInterfaces()` guard tests.
 *
 * On Android 10+ (Termux / PRoot), SELinux blocks Netlink `RTM_GETADDR` sockets, causing libuv's
 * `uv_interface_addresses` to fail with `ERR_SYSTEM_ERROR` (EACCES, errno -13). `@libp2p/utils`
 * (`get-thin-waist-addresses`) calls `os.networkInterfaces()` unguarded whenever a TCP listener
 * expands a wildcard address (`/ip4/0.0.0.0/tcp/0`), crashing the daemon during standing-receiver
 * startup.
 *
 * Clauses verified here:
 *   1. On platforms where `os.networkInterfaces()` succeeds (macOS, Linux, Windows), the guard
 *      returns the native interface dictionary untouched and never fires `onFallback`.
 *   2. When the underlying implementation throws (e.g. `ERR_SYSTEM_ERROR`), the guard catches the
 *      error, invokes `onFallback` with the upstream `code`, `errno`, `syscall`, and `message`,
 *      and returns a valid loopback interface map (`127.0.0.1` and `::1`).
 *   3. `syncBuiltinESMExports()` updates the `node:os` ESM namespace so both default imports
 *      (`import os from "node:os"`) and namespace/named reads see the guarded function.
 *   4. A real `createNode` configured with `/ip4/0.0.0.0/tcp/0` starts, binds, and expands its
 *      wildcard listen address to `/ip4/127.0.0.1/tcp/<port>` without crashing while the underlying
 *      `networkInterfaces` throws `ERR_SYSTEM_ERROR`.
 */

import { describe, it, expect, afterEach } from "vitest";
import os from "node:os";
import * as osNamespace from "node:os";
import { generateKeypair, type KeyProvider } from "@cello-protocol/crypto";
import {
  createNode,
  installSafeNetworkInterfacesGuard,
  type NetworkInterfacesFallbackEvent,
} from "../index.js";
import {
  setNetworkInterfacesImplForTest,
  uninstallSafeNetworkInterfacesGuardForTest,
} from "../network-interfaces-guard.js";

function makeKeyProvider(): KeyProvider {
  const inner = generateKeypair();
  return {
    getPublicKey: () => Promise.resolve(inner.getPublicKey()),
    sign: (data: Uint8Array) => Promise.resolve(inner.sign(data)),
  };
}

function makeProotSystemError(): NodeJS.ErrnoException {
  const err = new Error(
    "A system error occurred: uv_interface_addresses returned EACCES (permission denied)",
  ) as NodeJS.ErrnoException;
  err.code = "ERR_SYSTEM_ERROR";
  err.errno = -13;
  err.syscall = "uv_interface_addresses";
  return err;
}

describe("installSafeNetworkInterfacesGuard", () => {
  afterEach(() => {
    uninstallSafeNetworkInterfacesGuardForTest();
  });

  it("1. passes through the native interface map untouched when os.networkInterfaces() succeeds", () => {
    const fakeNative: NodeJS.Dict<os.NetworkInterfaceInfo[]> = {
      en0: [
        {
          address: "192.168.1.42",
          netmask: "255.255.255.0",
          family: "IPv4",
          mac: "aa:bb:cc:dd:ee:ff",
          internal: false,
          cidr: "192.168.1.42/24",
        },
      ],
    };
    const events: NetworkInterfacesFallbackEvent[] = [];

    installSafeNetworkInterfacesGuard({
      impl: () => fakeNative,
      onFallback: (e) => events.push(e),
    });

    const result = os.networkInterfaces();
    expect(result).toBe(fakeNative);
    expect(result["en0"]?.[0]?.address).toBe("192.168.1.42");
    expect(events).toEqual([]);
  });

  it("2. catches ERR_SYSTEM_ERROR, reports upstream cause via onFallback once per distinct code, and returns loopback interfaces", () => {
    const events: NetworkInterfacesFallbackEvent[] = [];
    let currentError: NodeJS.ErrnoException = makeProotSystemError();

    installSafeNetworkInterfacesGuard({
      impl: () => {
        throw currentError;
      },
      onFallback: (e) => events.push(e),
    });

    const first = os.networkInterfaces();
    const second = os.networkInterfaces();

    expect(first["lo"]).toBeDefined();
    expect(first["lo"]?.map((i) => ({ address: i.address, family: i.family, internal: i.internal }))).toEqual([
      { address: "127.0.0.1", family: "IPv4", internal: true },
      { address: "::1", family: "IPv6", internal: true },
    ]);
    expect(second["lo"]?.[0]?.address).toBe("127.0.0.1");
    expect(events).toHaveLength(1);

    // A second distinct error code MUST be reported (proving per-code dedup rather than a boolean).
    const eperm = new Error("uv_interface_addresses returned EPERM") as NodeJS.ErrnoException;
    eperm.code = "EPERM";
    eperm.errno = -1;
    eperm.syscall = "uv_interface_addresses";
    currentError = eperm;

    os.networkInterfaces();
    os.networkInterfaces();

    expect(events).toEqual([
      {
        code: "ERR_SYSTEM_ERROR",
        errno: -13,
        syscall: "uv_interface_addresses",
        message: "A system error occurred: uv_interface_addresses returned EACCES (permission denied)",
      },
      {
        code: "EPERM",
        errno: -1,
        syscall: "uv_interface_addresses",
        message: "uv_interface_addresses returned EPERM",
      },
    ]);
  });

  it("3. syncBuiltinESMExports propagates the guarded function to the node:os ESM namespace, and replacing onFallback clears prior code dedup", () => {
    installSafeNetworkInterfacesGuard({
      impl: () => {
        throw makeProotSystemError();
      },
    });

    expect(osNamespace.networkInterfaces).toBe(os.networkInterfaces);
    const viaNamespace = osNamespace.networkInterfaces();
    expect(viaNamespace["lo"]?.[0]?.address).toBe("127.0.0.1");

    // Registering onFallback after an earlier un-listened fallback still delivers the event.
    const lateEvents: NetworkInterfacesFallbackEvent[] = [];
    installSafeNetworkInterfacesGuard({
      onFallback: (e) => lateEvents.push(e),
    });
    os.networkInterfaces();
    expect(lateEvents).toHaveLength(1);
    expect(lateEvents[0]?.code).toBe("ERR_SYSTEM_ERROR");
  });

  it("4. createNode itself installs the guard so a CelloNode listening on /ip4/0.0.0.0/tcp/0 starts under PRoot failure", async () => {
    const events: NetworkInterfacesFallbackEvent[] = [];
    const unguardedBinding = os.networkInterfaces;

    // Stage the throwing impl WITHOUT pre-installing the wrapper on os.networkInterfaces, so
    // deleting installSafeNetworkInterfacesGuard() in createNode (node.ts) makes this test fail.
    setNetworkInterfacesImplForTest(
      () => {
        throw makeProotSystemError();
      },
      (e) => events.push(e),
    );
    expect(os.networkInterfaces).toBe(unguardedBinding);

    const kp = makeKeyProvider();
    const node = await createNode({
      keyProvider: kp,
      listenAddresses: ["/ip4/0.0.0.0/tcp/0"],
      nodeType: "standing_receiver",
      autonatResponder: { enabled: false },
    });
    expect(os.networkInterfaces).not.toBe(unguardedBinding);

    await node.start();
    try {
      const addrs = node.listenAddresses();
      expect(addrs.length).toBeGreaterThan(0);
      expect(addrs.some((a) => a.startsWith("/ip4/127.0.0.1/tcp/"))).toBe(true);
      expect(events.length).toBe(1);
      expect(events[0]?.code).toBe("ERR_SYSTEM_ERROR");
    } finally {
      await node.stop();
    }
  });
});
