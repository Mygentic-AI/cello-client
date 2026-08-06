/**
 * DOD-LOGOUT-EXIT-1 — `cello logout` reported the daemon stopped while the process was still alive
 * and still talking to a directory node.
 *
 * THE DEFECT, precisely. There are two shutdown paths and they were not symmetric:
 *
 *   signal path — bin/cello-daemon.ts:  await handle.stop(signal); process.exit(0);
 *   IPC path    — daemon.ts `shutdown`: stop("logout_requested") (un-awaited); return acknowledged;
 *                                        ...and nothing ever exits the process.
 *
 * The IPC path relied entirely on the event loop draining by itself. `stop()` releases the socket,
 * the lock file and the singleton lock — which are exactly the two facts `logout`'s `daemonGone()`
 * consults — so the daemon went handle-free while still running. Every local check then agreed it
 * was gone, and logout printed "Daemon stopped." while the process held an ESTABLISHED outbound
 * connection to a directory node. The handles being correctly released is WHY the lie hid.
 *
 * What keeps the loop alive in production (none of it cancelled by `stop()`): the unawaited
 * `void safeStop(node)` in signaling-connect.ts, an in-flight dial with no timeout, the Telegram
 * long-poll whose stop only bumps a generation counter, and in-flight registry/manifest fetches.
 *
 * Chasing those one at a time is unbounded — the NEXT straggler reintroduces the lie silently. The
 * fix is to make the IPC path symmetric with the signal path: `stop()` fires an `onStopped` hook as
 * its last act, and the binary wires that hook to `process.exit(0)`. `process.exit` may NOT live in
 * daemon.ts: in-process callers (vitest, embedders) would be killed.
 *
 * TEST TEETH. The binary case below spawns the real daemon WITH A LOADED AGENT, so per-agent
 * signaling comes up and the event loop is genuinely non-empty — the condition the pre-existing
 * AC4 test (cli commands.test.ts) does not create, which is why that test was green throughout.
 * It also asserts the `daemon.exit` event, so an implementation that deletes the bin wiring and
 * merely hopes the loop drains fails even on a machine where it happens to drain.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon } from "../ipc-client.js";
import { probeSingletonLock } from "../singleton-lock.js";
import { readLock } from "../lock-file.js";
import type { Logger, DaemonConfig } from "../types.js";

function nullLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

/** True while a process exists. Asserted on the PROCESS — never the lock file (AC4). */
function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

describe("DOD-LOGOUT-EXIT-1: the daemon must actually exit when logout says it stopped", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-logout-exit-"));
    handle = null;
  });

  afterEach(async () => {
    if (handle) {
      try {
        await handle.stop("test_cleanup");
      } catch {
        // already stopped
      }
    }
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeConfig(overrides?: Partial<DaemonConfig>): DaemonConfig {
    return {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: nullLogger(),
      ...overrides,
    };
  }

  // ─── AC1/AC2: the seam that lets the binary exit ────────────────────────────
  //
  // The hook is what makes the IPC path symmetric with the signal path. It must fire as the LAST
  // act of stop() — after the singleton lock is released — because the binary's handler is
  // `process.exit(0)`: anything sequenced after it would never run.

  it("fires onStopped after an IPC shutdown — the IPC path had no way to tell the binary to exit", async () => {
    const calls: string[] = [];
    handle = await startDaemon(makeConfig({ onStopped: () => { calls.push("stopped"); } }));

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    await client.send("shutdown");
    client.close();

    // stop() is deliberately un-awaited by the handler (the ack must flush first), so poll.
    await expect.poll(() => calls.length, { timeout: 10_000 }).toBe(1);
    handle = null;
  });

  it("fires onStopped LAST — at call time the singleton lock is already released and the lock file gone", async () => {
    // Ordering is load-bearing, not cosmetic. The binary's hook exits the process; if the hook fired
    // before `singletonLock.release()`, the process would die holding the kernel lock and the next
    // `cello login` would refuse to start beside a daemon that no longer exists.
    let lockStateAtHook: string | null = null;
    let lockFileAtHook: unknown = "not-checked";
    handle = await startDaemon(
      makeConfig({
        onStopped: async () => {
          lockStateAtHook = probeSingletonLock(tempDir, nullLogger());
          lockFileAtHook = await readLock(join(tempDir, "daemon.lock"));
        },
      }),
    );

    await handle.stop("direct_stop");
    handle = null;

    await expect.poll(() => lockStateAtHook, { timeout: 10_000 }).toBe("free");
    expect(lockFileAtHook).toBeNull();
  });

  it("fires onStopped on the DIRECT stop() path too — the signal path must not diverge again", async () => {
    const calls: string[] = [];
    handle = await startDaemon(makeConfig({ onStopped: () => { calls.push("stopped"); } }));

    await handle.stop("sigterm_equivalent");
    handle = null;

    expect(calls).toEqual(["stopped"]);
  });

  it("fires onStopped exactly once when shutdown is requested twice — a double exit is a lie about which stop finished", async () => {
    const calls: string[] = [];
    handle = await startDaemon(makeConfig({ onStopped: () => { calls.push("stopped"); } }));

    const a = await connectToDaemon(join(tempDir, "daemon.sock"));
    await a.send("shutdown");
    // The handler guards on `shutdownPromise`, so the second request must not start a second stop.
    try {
      await a.send("shutdown");
    } catch {
      // the server may already be tearing the connection down — that is fine, the point is the count
    }
    a.close();

    await expect.poll(() => calls.length, { timeout: 10_000 }).toBe(1);
    // Give a second stop a chance to appear before declaring exactly-once.
    await new Promise((r) => setTimeout(r, 500));
    expect(calls).toEqual(["stopped"]);
    handle = null;
  });

  // ─── The hook's own failure paths ───────────────────────────────────────────

  it("a THROWING onStopped propagates — the kill switch's own failure may not be swallowed", async () => {
    // If this throw were caught and logged, stop() would resolve normally and the daemon would sit
    // there alive and handle-free, while logout's socket and singleton checks both pass and it
    // prints "Daemon stopped." That is the original defect reached through the new code, so the
    // failure has to be loud enough to reach the caller.
    handle = await startDaemon(
      makeConfig({ onStopped: () => { throw new Error("exit_failed"); } }),
    );

    await expect(handle.stop("hook_throws")).rejects.toThrow("exit_failed");
    handle = null;
  });

  it("reports ok:false to onStopped when the teardown threw — a dirty stop must not look clean", async () => {
    // The binary exits NON-ZERO on ok:false. Without the outcome, a shutdown that failed halfway
    // (sessions never marked interrupted, DB never checkpointed) would exit 0 and logout would
    // report a clean stop — the same lie, one level up.
    const outcomes: Array<{ ok: boolean; error?: Error }> = [];
    const config = makeConfig({ onStopped: (o) => { outcomes.push(o); } });
    handle = await startDaemon(config);

    // Break the teardown from the outside: the session manager's graceful shutdown is on stop()'s
    // awaited path, so a throw there is a genuinely half-finished shutdown.
    const snm = handle.getSessionNodeManager() as unknown as { gracefulShutdown: () => Promise<void> };
    snm.gracefulShutdown = () => Promise.reject(new Error("teardown_blew_up"));

    await expect(handle.stop("dirty")).rejects.toThrow("teardown_blew_up");
    handle = null;

    expect(outcomes).toHaveLength(1);
    expect(outcomes[0]!.ok).toBe(false);
    expect(outcomes[0]!.error?.message).toBe("teardown_blew_up");
  });

  it("reports ok:true on a clean stop", async () => {
    const outcomes: Array<{ ok: boolean; error?: Error }> = [];
    handle = await startDaemon(makeConfig({ onStopped: (o) => { outcomes.push(o); } }));

    await handle.stop("clean");
    handle = null;

    expect(outcomes).toEqual([{ ok: true, error: undefined }]);
  });

  // ─── AC4: the real binary, with a non-empty event loop ──────────────────────

  /** Spawn the real daemon binary against this test's CELLO_DIR and wait until it is listening. */
  async function spawnDaemon(): Promise<{ child: ChildProcess; stdout: string[] }> {
    const daemonBin = join(import.meta.dirname, "../bin/cello-daemon.ts");
    const stdout: string[] = [];
    const child = spawn(process.execPath, ["--import", "tsx", daemonBin], {
      cwd: join(import.meta.dirname, "../.."),
      env: { ...process.env, CELLO_DIR: tempDir, CELLO_VERSION: "0.0.1-logout-exit-test" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout?.on("data", (b: Buffer) => { stdout.push(...b.toString().split("\n")); });
    await expect
      .poll(() => stdout.some((l) => l.includes("daemon.started")), { timeout: 60_000 })
      .toBe(true);
    return { child, stdout };
  }

  it(
    "AC4: the real binary, holding a LOADED AGENT, exits after an IPC shutdown — and says it was told to",
    async () => {
      // WHY THE AGENT MATTERS, and why creating a key file is not enough. The daemon loads agents
      // from the ENCRYPTED `agents` TABLE (agent-loader.ts `loadAgents` → DbIdentityStore.listAgents),
      // NOT from agents/<name>/key. A key file on disk inserts no row, so a daemon started beside
      // one loads nothing, brings up no per-agent signaling, and drains its own event loop — which
      // is exactly why the pre-existing AC4 test in the CLI suite stayed green while production
      // failed. So: create the agent through the daemon's own verb, then RESTART, so the second
      // daemon genuinely loads it at boot and brings its startup connections up.
      const first = await spawnDaemon();
      try {
        const setup = await connectToDaemon(join(tempDir, "daemon.sock"));
        await setup.send("cello_create_agent", { name: "logout-exit-agent" });
        await setup.send("shutdown");
        setup.close();
        await new Promise<void>((resolve) => { first.child.on("exit", () => resolve()); });
      } finally {
        if (first.child.exitCode === null && !first.child.killed) first.child.kill("SIGKILL");
      }

      let child: ChildProcess | null = null;
      try {
        const second = await spawnDaemon();
        child = second.child;
        const { stdout } = second;
        const pid = child.pid!;
        const exited = new Promise<void>((resolve) => { child!.on("exit", () => resolve()); });

        // The premise, asserted rather than assumed: this daemon really did load the agent. Without
        // this the test would silently go back to measuring an empty event loop the day the loader
        // changes — the failure mode it was written to escape.
        const started = stdout
          .filter((l) => l.includes("daemon.started"))
          .map((l) => JSON.parse(l) as { agentCount?: number });
        expect(started.length).toBeGreaterThan(0);
        expect(started[0]!.agentCount).toBeGreaterThanOrEqual(1);

        const client = await connectToDaemon(join(tempDir, "daemon.sock"));
        await client.send("shutdown");
        client.close();

        // THE assertion: the process is gone. Not the lock file — the process (AC4).
        await Promise.race([
          exited,
          new Promise((_, reject) => setTimeout(() => reject(new Error("daemon still alive 20s after shutdown")), 20_000)),
        ]);
        expect(isProcessAlive(pid)).toBe(false);

        // And it exited BECAUSE it was told to, cleanly. Without this the test also passes on a run
        // where the loop happens to drain, which would let the bin wiring be deleted unnoticed —
        // and `ok:true` is what separates a clean stop from one that threw halfway.
        const exitLine = stdout.find((l) => l.includes("daemon.exit"));
        expect(exitLine).toBeDefined();
        expect(JSON.parse(exitLine!)).toMatchObject({ event: "daemon.exit", ok: true });
        expect(child.exitCode).toBe(0);
      } finally {
        if (child && child.exitCode === null && !child.killed) child.kill("SIGKILL");
        child = null;
      }
    },
    180_000,
  );
});
