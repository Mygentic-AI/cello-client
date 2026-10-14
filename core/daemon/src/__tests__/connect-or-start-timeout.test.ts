/**
 * Unit 4: `connectOrStart` startup readiness budget and early boot logging tests.
 *
 * Clauses verified here:
 *   1. `DEFAULT_DAEMON_START_TIMEOUT_MS` is 30,000ms (30s), giving `cello-daemon` room to spawn
 *      the security gateway sidecar and probe directory `/bootstrap` endpoints on slower hosts
 *      (Android/PRoot, ARM, cold ONNX self-check) before `daemon.sock` opens.
 *   2. `connectOrStart` accepts `opts.startTimeoutMs` (or `CELLO_DAEMON_START_TIMEOUT_MS`) and
 *      succeeds when a spawned daemon opens its IPC socket before the deadline, and throws an
 *      error naming the configured timeout and including the `daemon.log` tail when a hung daemon
 *      never opens its socket.
 *   3. A daemon child that exits early with a non-zero code (other than `EXIT_ALREADY_RUNNING`)
 *      fails fast on the next poll tick without waiting for the full `startTimeoutMs` budget.
 *   4. `cello-daemon.ts` logs `daemon.boot.starting` at the start of `main()` before spawning the
 *      security gateway sidecar, so `daemon.log` records true process boot duration.
 */

import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  connectOrStart,
  DEFAULT_DAEMON_START_TIMEOUT_MS,
  CONTENDED_LOCK_RETRY_TIMEOUT_MS,
} from "../connect-or-start.js";
import { spawnRealDaemon, makeCelloDir, cleanupCelloDir, type SpawnedDaemon } from "./helpers/spawn-real-daemon.js";
import type { Logger } from "../types.js";

const silentLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

describe("connectOrStart startup timeout and early boot log", () => {
  const tempDirs: string[] = [];
  const childPids: number[] = [];
  let realDaemon: SpawnedDaemon | undefined;
  let realCelloDir: string | undefined;

  afterEach(async () => {
    for (const pid of childPids.splice(0)) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        // already exited
      }
    }
    if (realDaemon) {
      await realDaemon.stopGracefully().catch(() => realDaemon?.kill("SIGKILL"));
      realDaemon = undefined;
    }
    if (realCelloDir) {
      await cleanupCelloDir(realCelloDir);
      realCelloDir = undefined;
    }
    for (const d of tempDirs.splice(0)) {
      await rm(d, { recursive: true, force: true }).catch(() => {});
    }
  });

  it("1. exports 30s default start timeout for spawnDaemon while keeping 10s contended-lock retry timeout", () => {
    expect(DEFAULT_DAEMON_START_TIMEOUT_MS).toBe(30_000);
    expect(CONTENDED_LOCK_RETRY_TIMEOUT_MS).toBe(10_000);
  });

  it("2. times out after configured startTimeoutMs or CELLO_DAEMON_START_TIMEOUT_MS (with ms and whole-second formatting) and includes daemon.log tail", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cello-start-timeout-"));
    tempDirs.push(dir);
    const fakeBin = join(dir, "fake-hung-daemon.mjs");
    await writeFile(
      fakeBin,
      [
        'import { writeFileSync } from "node:fs";',
        'import { join } from "node:path";',
        'writeFileSync(join(process.env.CELLO_DIR, "pid.txt"), String(process.pid));',
        'process.stdout.write(JSON.stringify({ level: "info", event: "daemon.boot.starting", pid: process.pid }) + "\\n");',
        "setInterval(() => {}, 1000);",
      ].join("\n"),
      "utf8",
    );

    await expect(
      connectOrStart(dir, silentLogger, fakeBin, { startTimeoutMs: 450 }),
    ).rejects.toThrow(/Daemon failed to start within 450ms[\s\S]*daemon\.boot\.starting/);

    const { readFile } = await import("node:fs/promises");
    const pidText = await readFile(join(dir, "pid.txt"), "utf8").catch(() => "");
    if (pidText.trim()) {
      try { process.kill(Number(pidText.trim()), "SIGKILL"); } catch { /* exited */ }
    }

    // Exercise CELLO_DAEMON_START_TIMEOUT_MS env override (whole-second formatting) with opts omitted.
    const savedEnv = process.env["CELLO_DAEMON_START_TIMEOUT_MS"];
    process.env["CELLO_DAEMON_START_TIMEOUT_MS"] = "1000";
    try {
      await expect(
        connectOrStart(dir, silentLogger, fakeBin),
      ).rejects.toThrow(/Daemon failed to start within 1 second\.[\s\S]*daemon\.boot\.starting/);
    } finally {
      if (savedEnv === undefined) delete process.env["CELLO_DAEMON_START_TIMEOUT_MS"];
      else process.env["CELLO_DAEMON_START_TIMEOUT_MS"] = savedEnv;
    }

    const pidText2 = await readFile(join(dir, "pid.txt"), "utf8").catch(() => "");
    if (pidText2.trim()) childPids.push(Number(pidText2.trim()));
  });

  it("3. rejects malformed startTimeoutMs / CELLO_DAEMON_START_TIMEOUT_MS loudly instead of silently falling back, and fails fast on early child exit", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cello-start-fastfail-"));
    tempDirs.push(dir);
    const fakeBin = join(dir, "fake-crash-daemon.mjs");
    await writeFile(
      fakeBin,
      [
        'process.stderr.write("fatal_boot_error\\n");',
        "process.exit(1);",
      ].join("\n"),
      "utf8",
    );

    await expect(
      connectOrStart(dir, silentLogger, fakeBin, { startTimeoutMs: 0 }),
    ).rejects.toThrow(/Invalid startTimeoutMs \(0\): must be a positive integer/);

    const savedEnv = process.env["CELLO_DAEMON_START_TIMEOUT_MS"];
    process.env["CELLO_DAEMON_START_TIMEOUT_MS"] = "30s";
    try {
      await expect(
        connectOrStart(dir, silentLogger, fakeBin),
      ).rejects.toThrow(/Invalid CELLO_DAEMON_START_TIMEOUT_MS \("30s"\): must be a positive integer/);
    } finally {
      if (savedEnv === undefined) delete process.env["CELLO_DAEMON_START_TIMEOUT_MS"];
      else process.env["CELLO_DAEMON_START_TIMEOUT_MS"] = savedEnv;
    }

    const startedAt = Date.now();
    await expect(
      connectOrStart(dir, silentLogger, fakeBin, { startTimeoutMs: 15_000 }),
    ).rejects.toThrow(/Daemon exited \(code 1\) during startup[\s\S]*fatal_boot_error/);
    const elapsedMs = Date.now() - startedAt;
    expect(elapsedMs).toBeLessThan(3_000);
  });

  it("4. cello-daemon.ts logs daemon.boot.starting before security.gateway.spawned and daemon.started", async () => {
    realCelloDir = await makeCelloDir("cello-boot-log-order-");
    realDaemon = spawnRealDaemon(realCelloDir);
    await realDaemon.waitForEvent("daemon.started");

    const out = realDaemon.output();
    const bootIdx = out.indexOf('"event":"daemon.boot.starting"');
    const gwIdx = out.indexOf('"event":"security.gateway.spawned"');
    const startedIdx = out.indexOf('"event":"daemon.started"');

    expect(bootIdx).toBeGreaterThanOrEqual(0);
    expect(gwIdx).toBeGreaterThan(bootIdx);
    expect(startedIdx).toBeGreaterThan(gwIdx);
  }, 90_000);
});
