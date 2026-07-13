/**
 * DOD-DAEMON-CLEANUP-1 — an exiting daemon must not disarm a daemon it does not own.
 *
 * The defect (observed live 2026-07-10): the shutdown path unlinks `daemon.lock` and `daemon.sock`
 * unconditionally. When a DIFFERENT daemon has since taken those over, an exiting orphan deletes the
 * HEALTHY daemon's lock and socket — so `cello logout` reports "No daemon running" and the next
 * `cello login` spawns yet another daemon beside the live one. Killing the orphan sabotages the
 * survivor; the obvious recovery action propagates the bug.
 *
 * These tests spawn the REAL binary (separate pid). An in-process daemon shares the test runner's
 * pid, so a lock written with `process.pid` would look "ours" to it no matter what — it cannot
 * reproduce this class at all. That trap already bit DOD-LOGOUT-WAIT-1's first AC2 attempt.
 *
 * Each AC is asserted in BOTH directions: the daemon must leave a foreign lock/socket alone AND
 * still clean up its own. A fix that simply stops cleaning up anything would leak stale files into
 * every operator's ~/.cello and pass a one-sided test.
 */

import { describe, it, expect, afterEach } from "vitest";
import { createServer, type Server } from "node:net";
import { readFile, writeFile, stat, unlink } from "node:fs/promises";
import { join } from "node:path";
import {
  spawnRealDaemon,
  makeCelloDir,
  cleanupCelloDir,
  logEvents,
  type SpawnedDaemon,
} from "./helpers/spawn-real-daemon.js";

async function exists(p: string): Promise<boolean> {
  try { await stat(p); return true; } catch { return false; }
}

async function readLockPid(lockPath: string): Promise<number> {
  const parsed = JSON.parse(await readFile(lockPath, "utf-8")) as { pid: number };
  return parsed.pid;
}

describe("DOD-DAEMON-CLEANUP-1 — an exiting daemon must not disarm a daemon it does not own", () => {
  let celloDir: string | undefined;
  let daemon: SpawnedDaemon | undefined;
  let squatter: Server | undefined;

  afterEach(async () => {
    if (daemon) { daemon.kill("SIGKILL"); daemon = undefined; }
    if (squatter) { await new Promise<void>((r) => squatter!.close(() => r())); squatter = undefined; }
    await cleanupCelloDir(celloDir);
    celloDir = undefined;
  });

  // ── AC1: unlink daemon.lock ONLY if the lock's pid is our own ──

  it("AC1: leaves daemon.lock alone when the lock's pid is NOT its own, and says so", async () => {
    celloDir = await makeCelloDir();
    const lockPath = join(celloDir, "daemon.lock");

    daemon = spawnRealDaemon(celloDir);
    await daemon.waitForEvent("daemon.started");
    expect(await readLockPid(lockPath)).toBe(daemon.pid);

    // Simulate the cascade: a DIFFERENT daemon takes over the lock while this one is running.
    // The test runner's pid is a real, ALIVE pid that is not the daemon's — exactly the shape of a
    // healthy peer that has claimed the lock.
    const foreignPid = process.pid;
    const lock = JSON.parse(await readFile(lockPath, "utf-8")) as Record<string, unknown>;
    await writeFile(lockPath, JSON.stringify({ ...lock, pid: foreignPid }, null, 2) + "\n");

    const ownPid = daemon.pid;
    await daemon.stopGracefully();

    // The lock must survive, still pointing at the foreign owner.
    expect(await exists(lockPath)).toBe(true);
    expect(await readLockPid(lockPath)).toBe(foreignPid);

    // SI: the daemon that declines to remove a lock says so — at info, naming both pids.
    const declined = logEvents(daemon.output(), "daemon.lock.not_ours");
    expect(declined).toHaveLength(1);
    expect(declined[0].level).toBe("info");
    expect(declined[0].ownPid).toBe(ownPid);
    expect(declined[0].lockPid).toBe(foreignPid);
  }, 90_000);

  it("AC1: still removes daemon.lock on a clean shutdown when the lock IS its own", async () => {
    celloDir = await makeCelloDir();
    const lockPath = join(celloDir, "daemon.lock");

    daemon = spawnRealDaemon(celloDir);
    await daemon.waitForEvent("daemon.started");
    expect(await readLockPid(lockPath)).toBe(daemon.pid);

    await daemon.stopGracefully();

    expect(await exists(lockPath)).toBe(false);
    expect(logEvents(daemon.output(), "daemon.lock.not_ours")).toHaveLength(0);
  }, 90_000);

  // ── AC2: remove daemon.sock ONLY if this daemon created that socket ──

  it("AC2: leaves daemon.sock alone when it is not the socket this daemon created", async () => {
    celloDir = await makeCelloDir();
    const socketPath = join(celloDir, "daemon.sock");

    daemon = spawnRealDaemon(celloDir);
    await daemon.waitForEvent("daemon.started");
    const ours = await stat(socketPath);

    // Simulate the cascade: a DIFFERENT daemon rebinds the socket path. Its listen() unlinks our
    // socket and creates its own — a genuinely different inode at the same path.
    await unlink(socketPath);
    squatter = createServer();
    await new Promise<void>((resolve, reject) => {
      squatter!.once("error", reject);
      squatter!.listen(socketPath, () => resolve());
    });
    const theirs = await stat(socketPath);
    expect(theirs.ino).not.toBe(ours.ino);

    await daemon.stopGracefully();

    // The peer's socket must survive — deleting it is what leaves the healthy daemon unreachable.
    expect(await exists(socketPath)).toBe(true);
    expect((await stat(socketPath)).ino).toBe(theirs.ino);

    const declined = logEvents(daemon.output(), "daemon.ipc.socket.not_ours");
    expect(declined).toHaveLength(1);
    expect(declined[0].level).toBe("info");
  }, 90_000);

  it("AC2: still removes daemon.sock on a clean shutdown when it created that socket", async () => {
    celloDir = await makeCelloDir();
    const socketPath = join(celloDir, "daemon.sock");

    daemon = spawnRealDaemon(celloDir);
    await daemon.waitForEvent("daemon.started");
    expect(await exists(socketPath)).toBe(true);

    await daemon.stopGracefully();

    expect(await exists(socketPath)).toBe(false);
    expect(logEvents(daemon.output(), "daemon.ipc.socket.not_ours")).toHaveLength(0);
  }, 90_000);
});
