/**
 * DOD-SINGLE-DAEMON-1 — make two-daemons-at-once impossible, not merely unlikely.
 *
 * `daemon.lock` is a JSON file. A file is advisory: anyone can delete it, and a `kill -9` leaves it
 * behind pointing at a pid that no longer exists (or, worse, at a pid the OS has since REUSED for an
 * unrelated process). A file's existence cannot answer "is a daemon running?" — only the kernel can.
 *
 * So the daemon takes a real OS-level lock and holds it for its whole lifetime. The kernel releases
 * it on process death, including SIGKILL, so no stale state can survive a crash and no recovery step
 * is needed. `daemon.lock` keeps its metadata (it is how we NAME the holding pid in the error) but it
 * never DECIDES whether a daemon may start.
 *
 * Real spawned binaries throughout: a second daemon in the test's own process would share the test
 * runner's pid and its file locks, and could not contend for anything.
 */

import { describe, it, expect, afterEach } from "vitest";
import { execFileSync, spawn } from "node:child_process";
import { readFile, writeFile, stat, unlink } from "node:fs/promises";
import { join } from "node:path";
import { connectOrStart } from "../connect-or-start.js";
import { connectToDaemon } from "../ipc-client.js";
import { SINGLETON_LOCK_FILENAME, acquireSingletonLock } from "../singleton-lock.js";
import type { Logger } from "../types.js";
import {
  spawnRealDaemon,
  makeCelloDir,
  cleanupCelloDir,
  type SpawnedDaemon,
} from "./helpers/spawn-real-daemon.js";

const silentLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

async function exists(p: string): Promise<boolean> {
  try { await stat(p); return true; } catch { return false; }
}

/** The pids currently holding `file` open, per lsof. */
function holdersOf(file: string): number[] {
  try {
    const out = execFileSync("lsof", ["-t", file], { encoding: "utf-8" }).trim();
    return out ? out.split("\n").map((l) => Number(l.trim())).filter((n) => Number.isFinite(n)) : [];
  } catch {
    return []; // lsof exits non-zero when nothing holds the file
  }
}

describe("DOD-SINGLE-DAEMON-1 — a second daemon cannot start", () => {
  let celloDir: string | undefined;
  const spawned: SpawnedDaemon[] = [];

  afterEach(async () => {
    for (const d of spawned) d.kill("SIGKILL");
    spawned.length = 0;
    await cleanupCelloDir(celloDir);
    celloDir = undefined;
  });

  const spawnTracked = (dir: string): SpawnedDaemon => {
    const d = spawnRealDaemon(dir);
    spawned.push(d);
    return d;
  };

  it("AC1+AC2: a second daemon exits non-zero naming the holder, and never opens the DB", async () => {
    celloDir = await makeCelloDir();
    const dbPath = join(celloDir, "sessions.db");

    const first = spawnTracked(celloDir);
    await first.waitForEvent("daemon.started");
    expect(holdersOf(dbPath)).toEqual([first.pid]);

    // AC1: the OS lock is the MECHANISM, and this is the assertion that says so. Without it, an
    // implementation that never takes a kernel lock at all — just reads daemon.lock and checks the
    // pid is alive and holds sessions.db — passes every other assertion in this file. That is the
    // stale-file guesswork the whole unit exists to abolish, so the test must witness the kernel
    // lock itself, not merely its consequences.
    expect(holdersOf(join(celloDir, SINGLETON_LOCK_FILENAME))).toEqual([first.pid]);

    // A second daemon against the same CELLO_DIR — the orphan-restart case, verbatim.
    const second = spawnTracked(celloDir);
    const exit = await second.waitForExit();

    // AC2: it must refuse, loudly, and name the pid that holds the lock. Exit 3 is a contract:
    // "lost the race", distinct from 1 = "broken". Pin it or it rots.
    expect(exit.code).toBe(3);
    expect(second.output()).toContain("another daemon is already running");
    expect(second.output()).toContain(String(first.pid));

    // AC2: "never opens the DB, never registers agents, never connects to the directory" — assert
    // all three, not just the absence of daemon.started. These are the events that would prove it
    // got further than it was allowed to.
    expect(second.output()).not.toContain("daemon.started");
    expect(second.output()).not.toContain("agent.online");
    expect(second.output()).not.toContain("directory.signaling.connected");
    expect(holdersOf(dbPath)).toEqual([first.pid]);

    // The survivor is untouched: still the lock holder, still serving.
    expect(first.child.exitCode).toBeNull();
    const lock = JSON.parse(await readFile(join(celloDir, "daemon.lock"), "utf-8")) as { pid: number };
    expect(lock.pid).toBe(first.pid);
  }, 90_000);

  it("AC1: the lock is held for the daemon's LIFETIME, not just across startup", async () => {
    // The other tests race a second daemon in milliseconds after daemon.started. An implementation
    // that took the lock and dropped it at the end of startup would sail through them on timing
    // alone. So: let the daemon live, do real work, and only then contend — the lock must still be
    // there. (This is also the shape of the GC question: if the SQLite handle were collected and its
    // fd closed, the lock would silently vanish out from under a running daemon.)
    celloDir = await makeCelloDir();

    const first = spawnTracked(celloDir);
    await first.waitForEvent("daemon.started");

    // Real work through the real IPC surface, so the daemon is not merely idling at its start line.
    const client = await connectToDaemon(join(celloDir, "daemon.sock"));
    await client.send("cello_status");
    client.close();

    // Long enough for a startup-scoped lock to have been dropped, and for V8 to have had every
    // chance to collect anything collectable.
    await new Promise((r) => setTimeout(r, 3000));

    expect(holdersOf(join(celloDir, SINGLETON_LOCK_FILENAME))).toEqual([first.pid]);

    const second = spawnTracked(celloDir);
    expect((await second.waitForExit()).code).toBe(3);
    expect(second.output()).toContain(String(first.pid));
    expect(first.child.exitCode).toBeNull();
  }, 90_000);

  it("AC1: three daemons started SIMULTANEOUSLY — exactly one survives (atomicity, not a check-then-act)", async () => {
    // Every other test in this file starts the second daemon only AFTER the first has announced
    // itself. That tests the steady state, and a check-then-act implementation passes it easily:
    // "does anyone else hold the file open? no? then start" is correct whenever the answer has
    // already settled. It is wrong precisely when it matters — three daemons launched at the same
    // instant all look, all see nothing, and all proceed. Atomicity is the entire thing a kernel lock
    // buys over a heuristic, so it has to be the thing we test.
    celloDir = await makeCelloDir();

    const racers = [spawnTracked(celloDir), spawnTracked(celloDir), spawnTracked(celloDir)];

    // Wait for the field to settle: two must die, one must be serving.
    const deadline = Date.now() + 45_000;
    let survivors: SpawnedDaemon[] = [];
    let losers: SpawnedDaemon[] = [];
    while (Date.now() < deadline) {
      survivors = racers.filter((d) => d.child.exitCode === null);
      losers = racers.filter((d) => d.child.exitCode !== null);
      if (losers.length === 2 && survivors.length === 1) break;
      await new Promise((r) => setTimeout(r, 100));
    }

    expect(survivors).toHaveLength(1);
    expect(losers).toHaveLength(2);

    const winner = survivors[0];
    await winner.waitForEvent("daemon.started");

    // The two losers refused for the RIGHT reason, and neither touched the database.
    for (const loser of losers) {
      expect(loser.child.exitCode).toBe(3);
      expect(loser.output()).toContain("another daemon is already running");
      expect(loser.output()).not.toContain("daemon.started");
    }

    // One writer on the DB, one holder of the lock. This is the invariant the whole story protects.
    expect(holdersOf(join(celloDir, "sessions.db"))).toEqual([winner.pid]);
    expect(holdersOf(join(celloDir, SINGLETON_LOCK_FILENAME))).toEqual([winner.pid]);
  }, 90_000);

  it("AC2: a TRANSIENT holder (a probe) must not kill a daemon that is legitimately starting", async () => {
    // The bug this pins, in one line: `probeSingletonLock` does not READ the lock — it TAKES it. So
    // every `cello login`, `cello logout` and shim autostart is briefly a WRITER, and a daemon whose
    // own acquisition refused to wait would be killed by a question, then blame "another daemon is
    // already running" — naming a daemon that does not exist.
    //
    // A real second PROCESS takes the lock and lets go 600ms later, exactly as a probe does (only
    // slower, so the window is deterministic instead of a 1ms coin-flip). A starting daemon must ride
    // that out and come up. It must NOT be a check-then-die.
    //
    // Teeth: set DAEMON_ACQUIRE_BUSY_TIMEOUT_MS back to 0 and this goes red — verified.
    celloDir = await makeCelloDir();

    const holderBin = join(import.meta.dirname, "helpers/hold-singleton-lock.ts");
    const holder = spawn(process.execPath, ["--import", "tsx", holderBin, celloDir, "600"], {
      cwd: join(import.meta.dirname, "../.."),
      stdio: ["ignore", "pipe", "pipe"],
    });
    try {
      // Do not race the fixture: wait until the lock is provably held before contending for it.
      await new Promise<void>((resolve, reject) => {
        holder.stdout.on("data", (c: Buffer) => { if (c.toString().includes("held")) resolve(); });
        holder.on("exit", () => reject(new Error("lock holder exited before taking the lock")));
        setTimeout(() => reject(new Error("lock holder never reported 'held'")), 30_000);
      });

      // The daemon's own acquisition, contended by a holder that WILL let go. It must wait, not die.
      const acquired = acquireSingletonLock(celloDir, silentLogger);
      acquired.release();
    } finally {
      holder.kill("SIGKILL");
    }
  }, 90_000);

  it("AC1: kill -9 leaves nothing stale — the OS releases the lock and the next daemon starts", async () => {
    celloDir = await makeCelloDir();
    const lockPath = join(celloDir, "daemon.lock");

    const first = spawnTracked(celloDir);
    await first.waitForEvent("daemon.started");

    // SIGKILL: no shutdown handler runs, nothing is cleaned up. This is the case a file-existence
    // lock always gets wrong — daemon.lock survives, pointing at a dead pid.
    first.kill("SIGKILL");
    await first.waitForExit();
    expect(await exists(lockPath)).toBe(true);

    // A fresh daemon must start anyway: the kernel dropped the lock when the process died.
    const next = spawnTracked(celloDir);
    await next.waitForEvent("daemon.started");

    const lock = JSON.parse(await readFile(lockPath, "utf-8")) as { pid: number };
    expect(lock.pid).toBe(next.pid);
    expect(holdersOf(join(celloDir, "sessions.db"))).toEqual([next.pid]);
  }, 90_000);

  it("AC3: connectOrStart never spawns beside a live daemon, even with the socket destroyed", async () => {
    celloDir = await makeCelloDir();
    const lockPath = join(celloDir, "daemon.lock");
    const dbPath = join(celloDir, "sessions.db");

    const first = spawnTracked(celloDir);
    await first.waitForEvent("daemon.started");

    // The exact state DOD-DAEMON-CLEANUP-1 describes: a healthy daemon whose socket an exiting
    // orphan deleted. The lock's pid is alive; the socket is unreachable. Today connectOrStart reads
    // that as "stale", deletes the lock, and spawns a SECOND daemon onto the live one's database.
    await unlink(join(celloDir, "daemon.sock"));

    // A bin path that cannot execute: if connectOrStart tried to spawn, we would learn about it.
    await expect(
      connectOrStart(celloDir, silentLogger, "/nonexistent-daemon-bin"),
    ).rejects.toThrow(/already running/i);

    // It must not have disarmed the survivor on the way out...
    expect(await exists(lockPath)).toBe(true);
    const lock = JSON.parse(await readFile(lockPath, "utf-8")) as { pid: number };
    expect(lock.pid).toBe(first.pid);
    // ...and must not have put a second writer on the database.
    expect(holdersOf(dbPath)).toEqual([first.pid]);
    expect(first.child.exitCode).toBeNull();
  }, 90_000);

  it("AC4: a stale lock naming a REUSED pid must not wedge login — the OS lock decides, not the file", async () => {
    // The trap in a naive fix. After a crash the OS can hand the dead daemon's pid to an unrelated
    // process. `isProcessAlive(lock.pid)` then says "alive" forever, and a daemon that trusts the
    // FILE would refuse to start for good, with no way out but deleting ~/.cello by hand.
    // Nothing holds the OS lock here, so a daemon may start — whatever the JSON claims.
    celloDir = await makeCelloDir();
    const lockPath = join(celloDir, "daemon.lock");

    // The test runner: a real, alive pid that is emphatically not a daemon.
    await writeFile(
      lockPath,
      JSON.stringify({ pid: process.pid, socketPath: join(celloDir, "daemon.sock"), version: "0.0.1" }, null, 2),
    );

    // It must choose to SPAWN (which fails on this bin — that failure is the proof it tried) rather
    // than refuse with "already running".
    await expect(
      connectOrStart(celloDir, silentLogger, "/nonexistent-daemon-bin"),
    ).rejects.toThrow(/^(?!.*already running).*$/is);

    // And the real thing must actually come up in that directory.
    const daemon = spawnTracked(celloDir);
    await daemon.waitForEvent("daemon.started");
    const lock = JSON.parse(await readFile(lockPath, "utf-8")) as { pid: number };
    expect(lock.pid).toBe(daemon.pid);
  }, 90_000);
});
